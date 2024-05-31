use std::{
  collections::BTreeMap,
  ffi::{CString, OsString},
  mem::size_of,
  os::unix::prelude::OsStringExt,
  path::PathBuf,
};

use nix::{
  errno::Errno,
  libc::{c_long, clone_args, epoll_event, sigset_t, sockaddr, stat, statfs, timespec, timeval, timex},
  sys::ptrace::{self, AddressType},
  unistd::Pid,
};

use crate::{
  arch::PtraceRegisters,
  types::{cap_user_data, cap_user_header, futex_waitv, linux_dirent, linux_dirent64},
};

/// Inspect the registers captured by ptrace and return the inspection result.
pub trait FromInspectingRegs {
  fn from_inspecting_regs(pid: Pid, regs: &PtraceRegisters) -> Self;
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

impl InspectFromPid for Result<clone_args, InspectError> {
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

impl InspectFromPid for Result<i32, InspectError> {
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
