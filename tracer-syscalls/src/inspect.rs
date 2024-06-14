use std::{
  collections::BTreeMap,
  ffi::{CString, OsString},
  mem::size_of,
  os::unix::prelude::OsStringExt,
  path::PathBuf,
  sync::Arc,
};

use nix::{
  errno::Errno,
  libc::{
    c_long, epoll_event, fd_set, iocb, iovec, itimerspec, itimerval, mmsghdr, mq_attr, msghdr, msqid_ds, open_how, pollfd, rlimit, rlimit64, rusage, sched_attr, sched_param, sembuf, shmid_ds, sigaction, sigevent, siginfo_t, sigset_t, sockaddr, stack_t, stat, statfs, statx, sysinfo, timespec, timeval, timex, tms, utimbuf, utsname
  },
  sys::ptrace::{self, AddressType},
  unistd::Pid,
};

use crate::{
  arch::PtraceRegisters,
  types::{
    __aio_sigset, __mount_arg, cachestat, cachestat_range, cap_user_data, cap_user_header, futex_waitv, io_event, io_uring_params, kexec_segment, landlock_ruleset_attr, linux_dirent, linux_dirent64, mnt_id_req, mount_attr, rseq, statmount, timezone, ustat
  },
};

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

pub type InspectError = Errno;

impl InspectFromPid for Result<CString, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    read_cstring(pid, address)
  }
}

pub fn read_generic_string<TString>(
  pid: Pid,
  address: AddressType,
  ctor: impl Fn(Vec<u8>) -> TString,
) -> Result<TString, InspectError> {
  let mut buf = Vec::new();
  let mut address = address;
  const WORD_SIZE: usize = size_of::<c_long>();
  loop {
    let word = match ptrace::read(pid, address) {
      Err(e) => {
        return Err(e);
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
pub fn read_cstring(pid: Pid, address: AddressType) -> Result<CString, InspectError> {
  read_generic_string(pid, address, |x| CString::new(x).unwrap())
}

pub fn read_pathbuf(pid: Pid, address: AddressType) -> Result<PathBuf, InspectError> {
  read_generic_string(pid, address, |x| PathBuf::from(OsString::from_vec(x)))
}

pub fn read_lossy_string(pid: Pid, address: AddressType) -> Result<String, InspectError> {
  // Waiting on https://github.com/rust-lang/libs-team/issues/116
  read_generic_string(pid, address, |x| String::from_utf8_lossy(&x).into_owned())
}

pub fn read_null_ended_array<TItem>(
  pid: Pid,
  mut address: AddressType,
  reader: impl Fn(Pid, AddressType) -> Result<TItem, InspectError>,
) -> Result<Vec<TItem>, InspectError> {
  let mut res = Vec::new();
  const WORD_SIZE: usize = size_of::<c_long>();
  loop {
    let ptr = match ptrace::read(pid, address) {
      Err(e) => {
        return Err(e);
      }
      Ok(ptr) => ptr,
    };
    if ptr == 0 {
      return Ok(res);
    } else {
      res.push(reader(pid, ptr as AddressType)?);
    }
    address = unsafe { address.add(WORD_SIZE) };
  }
}

#[allow(unused)]
pub fn read_cstring_array(pid: Pid, address: AddressType) -> Result<Vec<CString>, InspectError> {
  read_null_ended_array(pid, address, read_cstring)
}

pub fn read_lossy_string_array(
  pid: Pid,
  address: AddressType,
) -> Result<Vec<String>, InspectError> {
  read_null_ended_array(pid, address, read_lossy_string)
}

impl InspectFromPid for Result<sockaddr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<PathBuf, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<Vec<u8>, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<timex, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<cap_user_data, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<cap_user_header, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<timespec, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<stack_t, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<mnt_id_req, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<shmid_ds, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<cachestat, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<cachestat_range, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<statx, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}


impl InspectFromPid for Result<utimbuf, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<ustat, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<utsname, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<itimerspec, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<tms, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sysinfo, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<nix::libc::clone_args, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<i64, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<u64, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<AddressType, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<u32, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<Arc<rseq>, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<Arc<statmount>, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<i32, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sched_attr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sembuf, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sched_param, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sigaction, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<epoll_event, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<stat, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<statfs, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<futex_waitv, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<itimerval, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<iocb, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<__aio_sigset, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<io_uring_params, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<io_event, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<kexec_segment, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<rlimit, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<rusage, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<timezone, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<linux_dirent, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<linux_dirent64, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<landlock_ruleset_attr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<__mount_arg, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

// impl<T> InspectFromPid for Result<T, InspectError>
// where
//   T: Sized,
// {
//   fn inspect_from(pid: Pid, address: AddressType) -> Self {
//     todo!()
//   }
// }

#[cfg(target_arch = "x86_64")]
impl InspectFromPid for Result<crate::types::user_desc, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<timeval, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<mount_attr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<mq_attr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<iovec, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<rlimit64, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<siginfo_t, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<pollfd, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<fd_set, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<open_how, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<msqid_ds, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sigevent, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<mmsghdr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<msghdr, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

#[cfg(target_arch = "riscv64")]
impl InspectFromPid for Result<crate::types::riscv_hwprobe, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T> InspectFromPid for Result<Vec<T>, InspectError>
where
  Result<T, InspectError>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T> InspectFromPid for Result<[T; 2], InspectError>
where
  Result<T, InspectError>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl InspectFromPid for Result<sigset_t, InspectError> {
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    todo!()
  }
}

impl<T> InspectFromPid for Result<Option<T>, InspectError>
where
  Result<T, InspectError>: InspectFromPid,
{
  fn inspect_from(pid: Pid, address: AddressType) -> Self {
    if address.is_null() {
      Ok(None)
    } else {
      Ok(Some(Result::<T, InspectError>::inspect_from(pid, address)?))
    }
  }
}
