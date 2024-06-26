//! This module contains the lowel level types used in syscalls that are not defined in libc crate.

#![allow(non_camel_case_types)]

mod dst;

pub use dst::*;

use std::ffi::c_void;

use nix::libc::{
  c_char, c_int, c_long, c_uint, c_ulong, c_ushort, ino64_t, off64_t, off_t, sigset_t, size_t,
};

pub type key_serial_t = i32; // https://github.com/Distrotech/keyutils/blob/9d52b8ab86931fb5a66fa5b567ea01875f31016e/keyutils.h#L22

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct cap_user_header {
  pub version: u32,
  pub pid: c_int,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct cap_user_data {
  pub effective: u32,
  pub permitted: u32,
  pub inheritable: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct futex_waitv {
  pub val: u64,
  pub uaddr: u64,
  pub flags: u32,
  pub __reserved: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct robust_list {
  pub next: *mut robust_list,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct robust_list_head {
  pub list: robust_list,
  pub futex_offset: c_long,
  pub list_op_pending: *mut robust_list,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct user_desc {
  pub entry_number: c_uint,
  pub base_addr: c_uint,
  pub limit: c_uint,
  pub bitflags: c_uint,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct linux_dirent {
  pub d_ino: c_ulong,
  pub d_off: off_t,
  pub d_reclen: c_ushort,
  pub d_name: *mut c_char,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct linux_dirent64 {
  pub d_ino: ino64_t,
  pub d_off: off64_t,
  pub d_reclen: c_ushort,
  pub d_type: c_char,
  pub d_name: *mut c_char,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct timezone {
  pub tz_minuteswest: c_int,
  pub tz_dsttime: c_int,
}

pub type aio_context_t = c_ulong;

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_event {
  pub data: u64,
  pub obj: u64,
  pub res: i64,
  pub res2: i64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct __aio_sigset {
  pub sigmask: *const sigset_t,
  pub sigsetsize: size_t,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_uring_params {
  pub sq_entries: u32,
  pub cq_entries: u32,
  pub flags: u32,
  pub sq_thread_cpu: u32,
  pub sq_thread_idle: u32,
  pub features: u32,
  pub wq_fd: i32,
  pub resv: [u32; 3],
  pub sq_off: io_sqring_offsets,
  pub cq_off: io_cqring_offsets,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_sqring_offsets {
  pub head: u32,
  pub tail: u32,
  pub ring_mask: u32,
  pub ring_entries: u32,
  pub flags: u32,
  pub dropped: u32,
  pub array: u32,
  pub resv1: u32,
  pub user_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct io_cqring_offsets {
  pub head: u32,
  pub tail: u32,
  pub ring_mask: u32,
  pub ring_entries: u32,
  pub overflow: u32,
  pub cqes: u32,
  pub flags: u32,
  pub resv1: u32,
  pub user_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct kexec_segment {
  pub buf: *mut c_void,
  pub bufsz: size_t,
  pub mem: *mut c_void,
  pub memsz: size_t,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum landlock_rule_type {
  LANDLOCK_RULE_PATH_BENEATH = 1,
  LANDLOCK_RULE_NET_PORT,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C, packed)]
pub struct landlock_path_beneath_attr {
  pub allowed_access: u64,
  pub parent_fd: i32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct landlock_ruleset_attr {
  pub handled_access_fs: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct __mount_arg {
  pub mnt_id: u64,
  pub request_mask: u64,
}

// Can't make a sane struct with DST array member in rust
// #[derive(Debug, Clone, PartialEq)]
// #[repr(C)]
// pub struct lsm_ctx {
//   id: u64,
//   flags: u64,
//   len: u64,
//   ctx_len: u64,
//   ctx: [u8; ctx_len],
// }

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct mount_attr {
  pub attr_set: u64,
  pub attr_clr: u64,
  pub propagation: u64,
  pub userns_fd: u64,
}

pub type qid_t = c_uint;

#[cfg(target_arch = "riscv64")]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct riscv_hwprobe {
  pub key: i64,
  pub value: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct mnt_id_req {
  pub size: u32,
  pub spare: u32,
  pub mnt_id: u64,
  pub param: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct ustat {
  pub f_tfree: c_int,
  pub f_tinode: ino64_t,
  pub f_fname: [c_char; 6],
  pub f_fpack: [c_char; 6],
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct cachestat_range {
  pub off: u64,
  pub len: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct cachestat {
  pub nr_cache: u64,
  pub nr_dirty: u64,
  pub nr_writeback: u64,
  pub nr_evicted: u64,
  pub nr_recently_evicted: u64,
}
