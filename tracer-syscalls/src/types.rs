//! This module contains the lowel level types used in syscalls that are not defined in libc crate.

#![allow(non_camel_case_types)]

use nix::libc::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort, ino64_t, off64_t, off_t};

pub type key_serial_t = i32; // https://github.com/Distrotech/keyutils/blob/9d52b8ab86931fb5a66fa5b567ea01875f31016e/keyutils.h#L22

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct cap_user_header {
  version: u32,
  pid: c_int,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct cap_user_data {
  effective: u32,
  permitted: u32,
  inheritable: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct futex_waitv {
  val: u64,
  uaddr: u64,
  flags: u32,
  __reserved: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct robust_list {
  next: *mut robust_list,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct robust_list_head {
  list: robust_list,
  futex_offset: c_long,
  list_op_pending: *mut robust_list,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct user_desc {
  entry_number: c_uint,
  base_addr: c_uint,
  limit: c_uint,
  bitflags: c_uint,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct linux_dirent {
  d_ino: c_ulong,
  d_off: off_t,
  d_reclen: c_ushort,
  d_name: *mut c_char,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct linux_dirent64 {
  d_ino: ino64_t,
  d_off: off64_t,
  d_reclen: c_ushort,
  d_type: c_char,
  d_name: *mut c_char,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct timezone {
  tz_minuteswest: c_int,
  tz_dsttime: c_int,
}
