//! This module contains the lowel level types used in syscalls that are not defined in libc crate.

#![allow(non_camel_case_types)]

use std::ffi::c_void;

use nix::libc::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort, ino64_t, off64_t, off_t, sigset_t, size_t};

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

pub type aio_context_t = c_ulong;

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_event {
  data: u64,
  obj: u64,
  res: i64,
  res2: i64,
}


#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct __aio_sigset {
  sigmask: *const sigset_t,
  sigsetsize: size_t,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_uring_params {
  sq_entries: u32,
  cq_entries: u32,
  flags: u32,
  sq_thread_cpu: u32,
  sq_thread_idle: u32,
  features: u32,
  wq_fd: i32,
  resv: [u32; 3],
  sq_off: io_sqring_offsets,
  cq_off: io_cqring_offsets,
}


#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_sqring_offsets {
  head: u32,
  tail: u32,
  ring_mask: u32,
  ring_entries: u32,
  flags: u32,
  dropped: u32,
  array: u32,
  resv1: u32,
  user_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_cqring_offsets {
  head: u32,
  tail: u32,
  ring_mask: u32,
  ring_entries: u32,
  overflow: u32,
  cqes: u32,
  flags: u32,
  resv1: u32,
  user_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct kexec_segment {
  buf: *mut c_void,
  bufsz: size_t,
  mem: *mut c_void,
  memsz: size_t,
}