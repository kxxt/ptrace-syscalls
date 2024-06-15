use std::{
  collections::BTreeMap,
  ffi::{CString, OsString},
  mem::{size_of, MaybeUninit},
  os::unix::prelude::OsStringExt,
  path::PathBuf,
  sync::Arc,
};

use nix::{
  errno::Errno,
  libc::{
    c_long, epoll_event, fd_set, iocb, iovec, itimerspec, itimerval, mmsghdr, mq_attr, msghdr,
    msqid_ds, open_how, pollfd, rlimit, rlimit64, rusage, sched_attr, sched_param, sembuf,
    shmid_ds, sigaction, sigevent, siginfo_t, sigset_t, sockaddr, stack_t, stat, statfs, statx,
    sysinfo, timespec, timeval, timex, tms, utimbuf, utsname,
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

/// Inspect the registers captured by ptrace and return the inspection result.
pub trait FromInspectingRegs {
  fn from_inspecting_regs(pid: Pid, regs: &PtraceRegisters) -> Self;
}

pub trait SyscallStopInspect {
  type RawArgs: Copy;
  type Args;
  type Result;
  fn inspect_sysenter(raw_args: Self::RawArgs) -> Self::Args;
  fn inspect_sysexit(raw_args: Self::RawArgs, regs: &PtraceRegisters) -> Self::Result;
}

/// Use ptrace to inspect the process with the given pid and return the inspection result.
///
/// This trait is implemented for syscall args structs intended to be used to gather syscall
/// arguments in ptrace syscall-enter-stop.
pub trait InspectFromPid {
  fn inspect_from(pid: Pid, address: AddressType) -> Self;
}

impl InspectFromPid for InspectResult<CString> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    read_cstring(pid, address)
  }
}

pub fn read_generic_string<TString: Clone + PartialEq>(
  pid: Pid,
  address: AddressType,
  ctor: impl Fn(Vec<u8>) -> TString,
) -> InspectResult<TString> {
  let mut buf = Vec::new();
  let mut address = address;
  const WORD_SIZE: usize = size_of::<c_long>();
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
pub fn read_cstring(pid: Pid, address: AddressType) -> InspectResult<CString> {
  read_generic_string(pid, address, |x| CString::new(x).unwrap())
}

pub fn read_pathbuf(pid: Pid, address: AddressType) -> InspectResult<PathBuf> {
  read_generic_string(pid, address, |x| PathBuf::from(OsString::from_vec(x)))
}

pub fn read_lossy_string(pid: Pid, address: AddressType) -> InspectResult<String> {
  // Waiting on https://github.com/rust-lang/libs-team/issues/116
  read_generic_string(pid, address, |x| String::from_utf8_lossy(&x).into_owned())
}

pub fn read_null_ended_array<TItem: Clone + PartialEq>(
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
pub fn read_cstring_array(pid: Pid, address: AddressType) -> InspectResult<Vec<CString>> {
  read_null_ended_array(pid, address, read_cstring)
}

pub fn read_lossy_string_array(pid: Pid, address: AddressType) -> InspectResult<Vec<String>> {
  read_null_ended_array(pid, address, read_lossy_string)
}

impl InspectFromPid for InspectResult<sockaddr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<PathBuf> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<Vec<u8>> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<timex> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<cap_user_data> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<cap_user_header> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<timespec> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<stack_t> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<mnt_id_req> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<shmid_ds> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<cachestat> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<cachestat_range> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<statx> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<utimbuf> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<ustat> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<utsname> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<itimerspec> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<tms> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sysinfo> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<nix::libc::clone_args> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<i64> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<u64> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<AddressType> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<u32> {
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

impl InspectFromPid for InspectResult<i32> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sched_attr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sembuf> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sched_param> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sigaction> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<epoll_event> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<stat> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<statfs> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<futex_waitv> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<itimerval> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<iocb> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<__aio_sigset> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<io_uring_params> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<io_event> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<kexec_segment> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<rlimit> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<rusage> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<timezone> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<linux_dirent> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<linux_dirent64> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<landlock_ruleset_attr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<__mount_arg> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

// impl<T> InspectFromPid for InspectResult<T>
// where
//   T: Sized,
// {
//   fn inspect_from(pid: Pid, address: AddressType) -> Self {
//     todo!()
//   }
// }

#[cfg(target_arch = "x86_64")]
impl InspectFromPid for InspectResult<crate::types::user_desc> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<timeval> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<mount_attr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<mq_attr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<iovec> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<rlimit64> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<siginfo_t> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<pollfd> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<fd_set> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<open_how> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<msqid_ds> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sigevent> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<mmsghdr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<msghdr> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

#[cfg(target_arch = "riscv64")]
impl InspectFromPid for InspectResult<crate::types::riscv_hwprobe> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T: Clone + PartialEq> InspectFromPid for InspectResult<Vec<T>>
where
  InspectResult<T>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T: Clone + PartialEq> InspectFromPid for InspectResult<[T; 2]>
where
  InspectResult<T>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for InspectResult<sigset_t> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
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
