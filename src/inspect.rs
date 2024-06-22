use std::{
    ffi::{CString, OsString},
    mem::{size_of, MaybeUninit},
    ops::{Add, Not},
    os::{raw::c_void, unix::prelude::OsStringExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nix::{
    errno::Errno,
    libc::{
        c_long, c_ulong, clone_args, epoll_event, fd_set, iocb, iovec, itimerspec, itimerval,
        memcpy, mmsghdr, mq_attr, msghdr, msqid_ds, open_how, pollfd, rlimit, rlimit64, rusage,
        sched_attr, sched_param, sembuf, shmid_ds, sigaction, sigevent, siginfo_t, sigset_t,
        sockaddr, stack_t, stat, statfs, statx, sysinfo, timespec, timeval, timex, tms, utimbuf,
        utsname,
    },
    sys::ptrace::{self, AddressType},
    unistd::{sysconf, Pid, SysconfVar},
};
use once_cell::sync::OnceCell;
use slice_dst::TryAllocSliceDst;

use crate::{
    arch::PtraceRegisters,
    types::{
        __aio_sigset, __mount_arg, cachestat, cachestat_range, cap_user_data, cap_user_header,
        futex_waitv, io_event, io_uring_params, kexec_segment, landlock_ruleset_attr, linux_dirent,
        linux_dirent64, mnt_id_req, mount_attr, rseq, statmount, timezone, ustat,
    },
};

pub fn ptrace_getregs(pid: Pid) -> Result<PtraceRegisters, Errno> {
    // Don't use GETREGSET on x86_64.
    // In some cases(it usually happens several times at and after exec syscall exit),
    // we only got 68/216 bytes into `regs`, which seems unreasonable. Not sure why.
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            ptrace::getregs(pid)
        } else {
            // https://github.com/torvalds/linux/blob/v6.9/include/uapi/linux/elf.h#L378
            // libc crate doesn't provide this constant when using musl libc.
            const NT_PRSTATUS: std::ffi::c_int	= 1;

            use nix::sys::ptrace::AddressType;

            let mut regs = std::mem::MaybeUninit::<PtraceRegisters>::uninit();
            let iovec = nix::libc::iovec {
                iov_base: regs.as_mut_ptr() as AddressType,
                iov_len: std::mem::size_of::<PtraceRegisters>(),
            };
            let ptrace_result = unsafe {
                nix::libc::ptrace(
                    nix::libc::PTRACE_GETREGSET,
                    pid.as_raw(),
                    NT_PRSTATUS,
                    &iovec as *const _ as *const nix::libc::c_void,
                )
            };
            let regs = if -1 == ptrace_result {
                let errno = nix::errno::Errno::last();
                return Err(errno);
            } else {
                assert_eq!(iovec.iov_len, std::mem::size_of::<PtraceRegisters>());
                unsafe { regs.assume_init() }
            };
            Ok(regs)
        }
    }
}

static PAGE_SIZE: OnceCell<usize> = OnceCell::new();
static SHOULD_USE_PROCESS_VM_READV: AtomicBool = AtomicBool::new(true);

/// Read a remote memory buffer and put it into dest.
unsafe fn read_remote_memory(
    pid: Pid,
    remote_addr: AddressType,
    len: usize,
    dest: AddressType,
) -> Result<usize, Errno> {
    // if the length is less than 2 words, use ptrace peek
    // TODO: This is heuristic and a benchmark is needed to determine the threshold.
    if len < WORD_SIZE * 2 {
        read_by_ptrace_peek(pid, remote_addr, len, dest)
    } else if SHOULD_USE_PROCESS_VM_READV.load(Ordering::Relaxed) {
        let result = read_by_process_vm_readv(pid, remote_addr, len, dest);
        result
            .map_err(|e| {
                SHOULD_USE_PROCESS_VM_READV.store(false, Ordering::SeqCst);
                e
            })
            .or_else(|_| read_by_ptrace_peek(pid, remote_addr, len, dest))
    } else {
        read_by_ptrace_peek(pid, remote_addr, len, dest)
    }
}

/// Read a remote memory buffer by ptrace peek and put it into dest.
unsafe fn read_by_ptrace_peek(
    pid: Pid,
    mut remote_addr: AddressType,
    mut len: usize,
    mut dest: AddressType,
) -> Result<usize, Errno> {
    // Check for address overflow.
    if (remote_addr as usize).checked_add(len).is_none() {
        return Err(Errno::EFAULT);
    }
    let mut total_read = 0;
    let align_bytes = (remote_addr as usize) & (WORD_SIZE - 1);
    if align_bytes != 0 {
        let aligned_addr = ((remote_addr as usize) & (WORD_SIZE - 1).not()) as AddressType;
        let word = ptrace::read(pid, aligned_addr)?;
        let copy_len = len.min(remote_addr as usize - align_bytes);
        memcpy(
            dest,
            (&word as *const c_long as *const c_void).byte_add(align_bytes),
            copy_len,
        );
        remote_addr = remote_addr.byte_add(copy_len);
        len -= copy_len;
        total_read += copy_len;
        dest = dest.byte_add(copy_len);
    }

    for _ in 0..(len / WORD_SIZE) {
        let word = ptrace::read(pid, remote_addr)?;
        memcpy(dest, &word as *const c_long as *const c_void, WORD_SIZE);
        dest = dest.byte_add(WORD_SIZE);
        remote_addr = remote_addr.byte_add(WORD_SIZE);
        total_read += WORD_SIZE;
    }

    let left_over = len & (WORD_SIZE - 1);
    if left_over > 0 {
        let word = ptrace::read(pid, remote_addr)?;
        memcpy(dest, &word as *const c_long as *const c_void, left_over);
        total_read += left_over;
    }
    Ok(total_read)
}

/// Read a remote memory buffer by process_vm_readv and put it into dest.
unsafe fn read_by_process_vm_readv(
    pid: Pid,
    remote_addr: AddressType,
    mut len: usize,
    dest: AddressType,
) -> Result<usize, Errno> {
    // liovcnt and riovcnt must be <= IOV_MAX
    const IOV_MAX: usize = nix::libc::_SC_IOV_MAX as usize;
    let mut riovs = [MaybeUninit::<nix::libc::iovec>::uninit(); IOV_MAX];
    let mut cur = remote_addr;
    let mut total_read = 0;
    while len > 0 {
        let dst_iov = iovec {
            iov_base: dest.byte_add(total_read),
            iov_len: len,
        };
        let mut riov_used = 0;
        while len > 0 {
            if riov_used == IOV_MAX {
                break;
            }

            // struct iovec uses void* for iov_base.
            if cur >= usize::MAX as AddressType {
                return Err(Errno::EFAULT);
            }
            riovs[riov_used].assume_init_mut().iov_base = cur;
            let page_size = *PAGE_SIZE.get_or_init(|| {
                sysconf(SysconfVar::PAGE_SIZE)
                    .expect("Failed to get page size")
                    .unwrap() as usize
            });
            let misalignment = (cur as usize) & (page_size - 1);
            let iov_len = (page_size - misalignment).min(len);
            len -= iov_len;
            // pointer types don't have checked_add ???
            cur = (cur as usize).checked_add(iov_len).ok_or(Errno::EFAULT)? as AddressType;
            riovs[riov_used].assume_init_mut().iov_len = iov_len;
            riov_used += 1;
        }
        let read = nix::libc::process_vm_readv(
            pid.into(),
            &dst_iov as *const _,
            1,
            &riovs as *const _ as *const iovec,
            riov_used as c_ulong,
            0,
        );
        if read == -1 {
            return Err(Errno::last());
        }
        total_read += read as usize;
    }
    Ok(total_read)
}

#[derive(Debug, Clone, PartialEq)]
pub enum InspectError<T: Clone + PartialEq> {
    /// The syscall failed thus the sysexit-stop inspection is not done.
    SyscallFailure,
    /// failed when trying to inspect the tracee memory.
    ReadFailure { errno: Errno, incomplete: Option<T> },
    /// A dependency inspection of this inspection failed.
    DependencyInspectFailure { field: &'static str },
}

pub type InspectResult<T> = Result<T, InspectError<T>>;

impl<T: Clone + PartialEq> InspectError<T> {
    pub fn map_ptrace_failure<U: Clone + PartialEq, F: FnOnce(T) -> U>(
        self,
        f: F,
    ) -> InspectError<U> {
        match self {
            InspectError::SyscallFailure => InspectError::SyscallFailure,
            InspectError::ReadFailure { errno, incomplete } => InspectError::ReadFailure {
                errno,
                incomplete: incomplete.map(f),
            },
            InspectError::DependencyInspectFailure { field } => {
                InspectError::DependencyInspectFailure { field }
            }
        }
    }
}

/// Inspect the arguments and results on sysenter/sysexit stops based on register values captured on sysenter.
pub trait SyscallStopInspect: Copy {
    type Args;
    type Result;
    fn inspect_sysenter(self, inspectee_pid: Pid) -> Self::Args;
    fn inspect_sysexit(self, inspectee_pid: Pid, regs: &PtraceRegisters) -> Self::Result;
}

/// Marker trait for sized repr(C) structs
///
/// # Safety
///
/// This trait should only be implemented for Sized repr(C) structs. Implementing this trait for other types will lead to undefined behavior.
pub(crate) unsafe trait ReprCMarker {}

macro_rules! impl_marker {
  ($marker:ty => $($ty:ty),*) => {
    $(unsafe impl $marker for $ty {})*
  };
}

impl_marker! {
  ReprCMarker =>
  u8, i32, u32, i64, u64, sockaddr, timex, cap_user_data, cap_user_header, timespec, stack_t, mnt_id_req,
  shmid_ds, cachestat, cachestat_range, statx, utimbuf, ustat, utsname, itimerspec, tms,
  sysinfo, clone_args, AddressType, sched_attr, sembuf, sched_param, sigaction, epoll_event, stat,
  statfs, futex_waitv, itimerval, iocb, __aio_sigset, io_uring_params, io_event, kexec_segment,
  rlimit, rusage, timezone, linux_dirent, linux_dirent64, landlock_ruleset_attr, __mount_arg,
  timeval, mount_attr, mq_attr, iovec, rlimit64, siginfo_t, pollfd, fd_set, open_how, msqid_ds,
  sigevent, mmsghdr, msghdr, sigset_t
}

// impl_marker! {
//   OptionMarker =>
//   // primitives
//   i64, u64, i32, u32,
//   // Special
//   CString, PathBuf, Vec<CString>,
//   // repr(C) structs
//   rusage, statfs, statx, timespec, timeval, timex, tms, utimbuf, utsname, itimerspec, sysinfo,
//   sigevent, stack_t, itimerval, sigaction, fd_set, rlimit64, sockaddr, epoll_event, sigset_t,
//   siginfo_t, mq_attr, timezone
// }

/// Use ptrace to inspect the process with the given pid and return the inspection result.
pub(crate) trait InspectFromPid {
    fn inspect_from(pid: Pid, address: AddressType) -> Self;
}

/// Use ptrace to inspect the process with the given pid and return the inspection result.
pub(crate) trait InspectCountedFromPid {
    fn inspect_from(pid: Pid, address: AddressType, count: usize) -> Self;
}

/// Use ptrace to inspect the process with the given pid and return the inspection result.
pub(crate) trait InspectDynSizedFromPid {
    fn inspect_from(pid: Pid, address: AddressType, size: usize) -> Self;
}

// TODO: impl process_vm_read and ptrace read
// https://android.googlesource.com/platform/system/core/+/android-9.0.0_r16/libunwindstack/Memory.cpp
const WORD_SIZE: usize = size_of::<c_long>();

impl<T: Clone + PartialEq + ReprCMarker> InspectFromPid for InspectResult<T> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        let mut buf = MaybeUninit::<T>::uninit();
        unsafe {
            read_remote_memory(
                pid,
                address,
                size_of::<T>(),
                buf.as_mut_ptr() as AddressType,
            )
            .map_err(|errno| InspectError::ReadFailure {
                errno,
                incomplete: None,
            })?;
            Ok(buf.assume_init())
        }
    }
}

impl InspectFromPid for InspectResult<CString> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        read_cstring(pid, address)
    }
}

fn read_generic_string<TString: Clone + PartialEq>(
    pid: Pid,
    address: AddressType,
    ctor: impl Fn(Vec<u8>) -> TString,
) -> InspectResult<TString> {
    let mut buf = Vec::new();
    let mut address = address;
    loop {
        let word = match ptrace::read(pid, address) {
            Err(e) => {
                return Err(InspectError::ReadFailure {
                    errno: e,
                    incomplete: Some(ctor(buf)),
                });
            }
            Ok(word) => word,
        };
        let word_bytes = word.to_ne_bytes();
        for &byte in word_bytes.iter() {
            if byte == 0 {
                return Ok(ctor(buf));
            }
            buf.push(byte);
        }
        address = unsafe { address.add(WORD_SIZE) };
    }
}

#[allow(unused)]
fn read_cstring(pid: Pid, address: AddressType) -> InspectResult<CString> {
    read_generic_string(pid, address, |x| CString::new(x).unwrap())
}

fn read_pathbuf(pid: Pid, address: AddressType) -> InspectResult<PathBuf> {
    read_generic_string(pid, address, |x| PathBuf::from(OsString::from_vec(x)))
}

fn read_lossy_string(pid: Pid, address: AddressType) -> InspectResult<String> {
    // Waiting on https://github.com/rust-lang/libs-team/issues/116
    read_generic_string(pid, address, |x| String::from_utf8_lossy(&x).into_owned())
}

fn read_null_ended_array<TItem: Clone + PartialEq>(
    pid: Pid,
    mut address: AddressType,
) -> InspectResult<Vec<TItem>>
where
    InspectResult<TItem>: InspectFromPid,
{
    let mut res = Vec::new();
    const WORD_SIZE: usize = size_of::<c_long>();
    loop {
        let ptr = match ptrace::read(pid, address) {
            Err(errno) => {
                return Err(InspectError::ReadFailure {
                    errno,
                    incomplete: Some(res),
                });
            }
            Ok(ptr) => ptr,
        };
        if ptr == 0 {
            return Ok(res);
        } else {
            match InspectResult::<TItem>::inspect_from(pid, ptr as AddressType) {
                Ok(item) => res.push(item),
                Err(e) => return Err(e.map_ptrace_failure(|_| res)),
            };
        }
        address = unsafe { address.add(WORD_SIZE) };
    }
}

impl InspectFromPid for InspectResult<PathBuf> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        read_pathbuf(pid, address)
    }
}

impl InspectFromPid for InspectResult<Arc<statmount>> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        todo!()
    }
}

#[cfg(target_arch = "x86_64")]
impl_marker! {
  ReprCMarker => crate::types::user_desc
}

#[cfg(target_arch = "riscv64")]
impl_marker! {
  ReprCMarker => crate::types::riscv_hwprobe
}

// TODO: speed up the read of Vec<u8>
// FIXME: some Vec are not null-terminated
impl InspectFromPid for InspectResult<Vec<u8>> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        read_null_ended_array::<u8>(pid, address)
    }
}

impl InspectFromPid for InspectResult<Vec<CString>> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        read_null_ended_array::<CString>(pid, address)
    }
}

impl<T: Clone + PartialEq> InspectCountedFromPid for InspectResult<Vec<T>>
where
    InspectResult<T>: InspectFromPid,
{
    fn inspect_from(pid: Pid, address: AddressType, count: usize) -> Self {
        let mut res = Vec::with_capacity(count);
        for i in 0..count {
            let item_address = unsafe { address.byte_add(i * size_of::<T>()) };
            let item = match InspectResult::<T>::inspect_from(pid, item_address) {
                Ok(item) => item,
                Err(e) => {
                    return Err(e.map_ptrace_failure(|incomplete| {
                        res.push(incomplete);
                        res
                    }));
                }
            };
            res.push(item);
        }
        Ok(res)
    }
}

impl<T: Clone + PartialEq> InspectFromPid for Result<[T; 2], InspectError<Vec<T>>>
where
    InspectResult<T>: InspectFromPid,
{
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        let item1 = InspectResult::<T>::inspect_from(pid, address)
            .map_err(|e| e.map_ptrace_failure(|incomplete| vec![incomplete]))?;
        let item2 =
            match InspectResult::<T>::inspect_from(pid, unsafe { address.add(size_of::<T>()) }) {
                Ok(t) => t,
                Err(e) => return Err(e.map_ptrace_failure(|incomplete| vec![item1, incomplete])),
            };
        Ok([item1, item2])
    }
}

impl<T: Clone + PartialEq + ReprCMarker> InspectFromPid for InspectResult<Option<T>> {
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        if address.is_null() {
            Ok(None)
        } else {
            Ok(Some(
                InspectResult::<T>::inspect_from(pid, address)
                    .map_err(|e| e.map_ptrace_failure(Some))?,
            ))
        }
    }
}

macro_rules! impl_inspect_from_pid_for_option {
  ($($ty:ty),*) => {
    $(
      impl InspectFromPid for InspectResult<Option<$ty>> {
        fn inspect_from(pid: Pid, address: AddressType) -> Self {
          if address.is_null() {
            Ok(None)
          } else {
            Ok(Some(
              <InspectResult::<$ty> as InspectFromPid>::inspect_from(pid, address).map_err(|e| e.map_ptrace_failure(Some))?,
            ))
          }
        }
      }
    )*
  };
}

macro_rules! impl_inspect_counted_from_pid_for_option {
  ($($ty:ty),*) => {
    $(
      impl InspectCountedFromPid for InspectResult<Option<$ty>> {
        fn inspect_from(pid: Pid, address: AddressType, count: usize) -> Self {
          if address.is_null() {
            Ok(None)
          } else {
            Ok(Some(
              <InspectResult::<$ty> as InspectCountedFromPid>::inspect_from(pid, address, count).map_err(|e| e.map_ptrace_failure(Some))?,
            ))
          }
        }
      }
    )*
  };
}

impl_inspect_from_pid_for_option! {
  PathBuf, CString, Vec<CString>
}

impl_inspect_counted_from_pid_for_option! {
  Vec<u64>, Vec<u32>
}

impl<T: Clone + PartialEq> InspectFromPid for Result<Option<[T; 2]>, InspectError<Vec<T>>>
where
    Result<[T; 2], InspectError<Vec<T>>>: InspectFromPid,
{
    fn inspect_from(pid: Pid, address: AddressType) -> Self {
        if address.is_null() {
            Ok(None)
        } else {
            Ok(Some(
                Result::<[T; 2], InspectError<Vec<T>>>::inspect_from(pid, address)
                    .map_err(|e| e.map_ptrace_failure(|incomplete| incomplete))?,
            ))
        }
    }
}

macro_rules! impl_inspect_dst {
  ($($t:ty),*) => {
    $(
      impl InspectDynSizedFromPid for InspectResult<Arc<$t>> {
        fn inspect_from(pid: Pid, address: AddressType, size: usize) -> Self {
          let arc = unsafe {
            Arc::<$t>::try_new_slice_dst(size, |ptr| {
              let read = read_remote_memory(pid, address, size, ptr.as_ptr() as AddressType)?;
              if read != size {
                return Err(Errno::EIO);
              } else {
                Ok(())
              }
            })
          }
          .map_err(|e| InspectError::ReadFailure {
            errno: e,
            incomplete: None,
          })?;
          Ok(arc)
        }
      }
    )*
  };
}

impl_inspect_dst!(rseq, statmount);
