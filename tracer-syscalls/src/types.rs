//! This module contains the lowel level types used in syscalls that are not defined in libc crate.

#![allow(non_camel_case_types)]

use nix::libc::c_int;

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