use std::{
  collections::BTreeMap,
  ffi::{CString, OsString},
  mem::{size_of, MaybeUninit},
  os::{raw::c_void, unix::prelude::OsStringExt},
  path::PathBuf,
  sync::Arc,
};

use itertools::chain;
use nix::{
  errno::Errno,
  libc::{
    c_int, c_long, clone_args, epoll_event, fd_set, iocb, iovec, itimerspec, itimerval, mmsghdr,
    mq_attr, msghdr, msqid_ds, open_how, pollfd, rlimit, rlimit64, rusage, sched_attr, sched_param,
    sembuf, shmid_ds, sigaction, sigevent, siginfo_t, sigset_t, sockaddr, stack_t, stat, statfs,
    statx, sysinfo, timespec, timeval, timex, tms, utimbuf, utsname,
  },
  sys::ptrace::{self, AddressType},
  unistd::Pid,
};

use crate::{
  arch::PtraceRegisters,
  types::{
    __aio_sigset, __mount_arg, cachestat, cachestat_range, cap_user_data, cap_user_header,
    futex_waitv, io_event, io_uring_params, kexec_segment, landlock_ruleset_attr, linux_dirent,
    linux_dirent64, mnt_id_req, mount_attr, rseq, statmount, timezone, ustat,
  },
};

#[derive(Debug, Clone, PartialEq)]
pub enum InspectError<T: Clone + PartialEq> {
  /// The syscall failed thus the sysexit-stop inspection is not done.
  SyscallFailure,
  /// Ptrace failed when trying to inspect the tracee memory.
  PtraceFailure { errno: Errno, incomplete: Option<T> },
}

pub type InspectResult<T> = Result<T, InspectError<T>>;

/// Inspect the arguments and results on sysenter/sysexit stops based on register values captured on sysenter.
pub(crate) trait SyscallStopInspect: Copy {
  type Args;
  type Result;
  fn inspect_sysenter(self, inspectee_pid: Pid) -> Self::Args;
  fn inspect_sysexit(self, inspectee_pid: Pid, regs: &PtraceRegisters) -> Self::Result;
}

/// Use ptrace to inspect the process with the given pid and return the inspection result.
pub(crate) trait InspectFromPid {
  fn inspect_from(pid: Pid, address: AddressType) -> Self;
}

const WORD_SIZE: usize = size_of::<c_long>();

#[repr(transparent)]
#[derive(Debug, Clone, PartialEq)]
struct SizedWrapper<T>(T);

impl<T: Clone + PartialEq> InspectFromPid for InspectResult<SizedWrapper<T>> {
  fn inspect_from(pid: Pid, mut address: AddressType) -> Self {
    let mut buf = MaybeUninit::<T>::uninit();
    let mut ptr = buf.as_mut_ptr() as *mut c_long;
    let ptr_end = unsafe { ptr.add(size_of::<T>()) };
    while ptr < ptr_end {
      let word = match ptrace::read(pid, address) {
        Err(errno) => {
          return Err(InspectError::PtraceFailure {
            errno,
            incomplete: None,
          });
        }
        Ok(word) => word,
      };
      let remain = unsafe { ptr_end.offset_from(ptr) } as usize;
      if remain < WORD_SIZE {
        let word_bytes = word.to_ne_bytes();
        for (idx, &byte) in word_bytes.iter().take(remain).enumerate() {
          unsafe {
            let ptr = (ptr as *mut u8).add(idx);
            *ptr = byte;
          }
        }
        break;
      } else {
        unsafe {
          *ptr = word;
          ptr = ptr.add(WORD_SIZE);
          address = address.add(WORD_SIZE);
        }
      }
    }
    unsafe { Ok(SizedWrapper(buf.assume_init())) }
  }
}

macro_rules! impl_inspect_for_sized {
  ($($ty:ty),*) => {
    $(
      impl InspectFromPid for InspectResult<$ty> {
        fn inspect_from(pid: Pid, address: AddressType) -> Self {
          InspectResult::<SizedWrapper<$ty>>::inspect_from(pid, address)
            .map(|x|x.0)
            .map_err(
              |e| match e {
                InspectError::SyscallFailure => InspectError::SyscallFailure,
                InspectError::PtraceFailure { errno, incomplete } => InspectError::PtraceFailure {
                  errno,
                  incomplete: incomplete.map(|x|x.0),
                },
              }
            )
        }
      }
    )*
  };
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
        return Err(InspectError::PtraceFailure {
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
  reader: impl Fn(Pid, AddressType) -> InspectResult<TItem>,
) -> InspectResult<Vec<TItem>> {
  let mut res = Vec::new();
  const WORD_SIZE: usize = size_of::<c_long>();
  loop {
    let ptr = match ptrace::read(pid, address) {
      Err(errno) => {
        return Err(InspectError::PtraceFailure {
          errno,
          incomplete: Some(res),
        });
      }
      Ok(ptr) => ptr,
    };
    if ptr == 0 {
      return Ok(res);
    } else {
      match reader(pid, ptr as AddressType) {
        Ok(item) => res.push(item),
        Err(InspectError::PtraceFailure {
          errno,
          incomplete: _,
        }) => {
          return Err(InspectError::PtraceFailure {
            errno,
            incomplete: Some(res),
          })
        }
        Err(InspectError::SyscallFailure) => return Err(InspectError::SyscallFailure),
      };
    }
    address = unsafe { address.add(WORD_SIZE) };
  }
}

#[allow(unused)]
fn read_cstring_array(pid: Pid, address: AddressType) -> InspectResult<Vec<CString>> {
  read_null_ended_array(pid, address, read_cstring)
}

fn read_lossy_string_array(pid: Pid, address: AddressType) -> InspectResult<Vec<String>> {
  read_null_ended_array(pid, address, read_lossy_string)
}

impl InspectFromPid for InspectResult<PathBuf> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    read_pathbuf(pid, address)
  }
}

impl InspectFromPid for InspectResult<Vec<u8>> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<Arc<rseq>> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<Arc<statmount>> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl_inspect_for_sized! {
  i32, u32, i64, u64, sockaddr, timex, cap_user_data, cap_user_header, timespec, stack_t, mnt_id_req,
  shmid_ds, cachestat, cachestat_range, statx, utimbuf, ustat, utsname, itimerspec, tms,
  sysinfo, clone_args, AddressType, sched_attr, sembuf, sched_param, sigaction, epoll_event, stat,
  statfs, futex_waitv, itimerval, iocb, __aio_sigset, io_uring_params, io_event, kexec_segment,
  rlimit, rusage, timezone, linux_dirent, linux_dirent64, landlock_ruleset_attr, __mount_arg,
  timeval, mount_attr, mq_attr, iovec, rlimit64, siginfo_t, pollfd, fd_set, open_how, msqid_ds,
  sigevent, mmsghdr, msghdr, sigset_t
}

#[cfg(target_arch = "x86_64")]
impl_inspect_for_sized! {
  crate::types::user_desc
}

#[cfg(target_arch = "riscv64")]
impl_inspect_for_sized! {
  crate::types::riscv_hwprobe
}

impl<T: Clone + PartialEq> InspectFromPid for InspectResult<Vec<T>>
where
  InspectResult<T>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T: Clone + PartialEq> InspectFromPid for Result<[T; 2], InspectError<Vec<T>>>
where
  InspectResult<T>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    let item1 = InspectResult::<T>::inspect_from(pid, address).map_err(|e| match e {
      InspectError::SyscallFailure => InspectError::SyscallFailure,
      InspectError::PtraceFailure { errno, incomplete } => InspectError::PtraceFailure {
        errno,
        incomplete: Some(incomplete.into_iter().collect::<Vec<T>>()),
      },
    })?;
    let item2 = match InspectResult::<T>::inspect_from(pid, unsafe { address.add(size_of::<T>()) })
    {
      Ok(t) => t,
      Err(e) => match e {
        InspectError::SyscallFailure => return Err(InspectError::SyscallFailure),
        InspectError::PtraceFailure { errno, incomplete } => {
          return Err(InspectError::PtraceFailure {
            errno,
            incomplete: Some(
              chain!(Some(item1), incomplete)
                .into_iter()
                .collect::<Vec<T>>(),
            ),
          })
        }
      },
    };
    Ok([item1, item2])
  }
}

impl<T: Clone + PartialEq> InspectFromPid for InspectResult<Option<T>>
where
  InspectResult<T>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    if address.is_null() {
      Ok(None)
    } else {
      Ok(Some(
        InspectResult::<T>::inspect_from(pid, address).map_err(|e| match e {
          InspectError::SyscallFailure => InspectError::SyscallFailure,
          InspectError::PtraceFailure { errno, incomplete } => InspectError::PtraceFailure {
            errno,
            incomplete: Some(incomplete),
          },
        })?,
      ))
    }
  }
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
        Result::<[T; 2], InspectError<Vec<T>>>::inspect_from(pid, address).map_err(
          |e| match e {
            InspectError::SyscallFailure => InspectError::SyscallFailure,
            InspectError::PtraceFailure { errno, incomplete } => {
              InspectError::PtraceFailure { errno, incomplete }
            }
          },
        )?,
      ))
    }
  }
}
