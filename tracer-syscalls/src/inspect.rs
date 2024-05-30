use std::{
  collections::BTreeMap,
  ffi::{CString, OsString},
  mem::size_of,
  os::unix::prelude::OsStringExt,
  path::PathBuf,
};

use nix::{
  errno::Errno,
  libc::{c_long, sockaddr},
  sys::ptrace::{self, AddressType},
  unistd::Pid,
};

use crate::arch::PtraceRegisters;

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
