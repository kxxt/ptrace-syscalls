#![allow(non_upper_case_globals)]

use std::path::PathBuf;
use std::{
  ffi::{c_int, CString},
  os::fd::RawFd,
};

use nix::libc::{c_char, c_uint, c_ulong, size_t, sockaddr, socklen_t, timex, mode_t, uid_t, gid_t, clockid_t};
use nix::sys::ptrace::AddressType;
use nix::unistd::Pid;
use tracer_syscalls_macros::gen_syscalls;

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, PtraceRegisters},
  types::*,
  FromInspectingRegs, SyscallNumber,
};

#[derive(Debug, Clone, PartialEq)]
pub struct UnknownArgs {
  pub number: isize,
  pub args: [usize; 6],
}

impl SyscallNumber for UnknownArgs {
  fn syscall_number(&self) -> isize {
    self.number
  }
}

impl FromInspectingRegs for UnknownArgs {
  fn from_inspecting_regs(_pid: Pid, regs: &PtraceRegisters) -> Self {
    let number = syscall_no_from_regs!(regs) as isize;
    let args = [
      syscall_arg!(regs, 0) as usize,
      syscall_arg!(regs, 1) as usize,
      syscall_arg!(regs, 2) as usize,
      syscall_arg!(regs, 3) as usize,
      syscall_arg!(regs, 4) as usize,
      syscall_arg!(regs, 5) as usize,
    ];
    UnknownArgs { number, args }
  }
}

gen_syscalls! {
  fake (number: i32) / { number: i32 } -> i32 for [x86_64: 0, aarch64: 0, riscv64: 0],
  // _llseek (32bit)
  // _newselect
  accept (socketfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int+addr+addrlen for [x86_64: 43, aarch64: 202, riscv64: 202],
  accept4 (socketfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t, flags: c_int } -> c_int+addr+addrlen for [x86_64: 288, aarch64: 242, riscv64: 242],
  access (pathname: *const c_char, mode: c_int) / { pathname: PathBuf, mode: c_int } -> c_int for [x86_64: 21],
  acct (filename: *const c_char) / { filename: Option<PathBuf> } -> c_int for [x86_64: 163, aarch64: 89, riscv64: 89],
  add_key (r#type: *const c_char, description: *const c_char, payload: *const c_void, plen: size_t, keyring: key_serial_t ) /
    { r#type: CString, description: CString, payload: Vec<u8>, plen: size_t, keyring: key_serial_t }
    -> key_serial_t for [x86_64: 248, aarch64: 217, riscv64: 217],
  adjtimex (buf: *mut timex) / { buf: timex } -> c_int for [x86_64: 159, aarch64: 171, riscv64: 171],
  alarm (seconds: c_uint) / { seconds: c_uint } -> c_uint for [x86_64: 37],
  // arc_gettls, arc_settls, arc_usr_cmpxchg
  arch_prctl (code: c_int, addr: c_ulong) / { code: c_int, addr: c_ulong } -> c_int for [x86_64: 158], // TODO: addr can be a ptr
  // arm_fadvise64_64, atomic_barrier, atomic_barrier
  bind (socketfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int for [x86_64: 49, aarch64: 200, riscv64: 200],
  // TODO: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L1454 and https://www.man7.org/linux/man-pages/man2/bpf.2.html
  bpf (cmd: c_int, attr: *mut c_void, size: c_uint) /
    { cmd: c_int, attr: Vec<u8>, size: c_uint } -> c_int for [x86_64: 321, aarch64: 280, riscv64: 280],
  brk (addr: *mut c_void) / { addr: AddressType } -> c_int for [x86_64: 12, aarch64: 214, riscv64: 214],
  // cachectl, cacheflush
  // cachestat { fd: RawFd, cstat_range: cachestat_range, cstat: cachestat, flags: c_uint } // TODO: https://github.com/golang/go/issues/61917
  capget (hdrp: *mut cap_user_header, datap: *mut cap_user_data) / { } -> c_int+hdrp+datap for [x86_64: 125, aarch64: 90, riscv64: 90],
  capset (hdrp: *mut cap_user_header, datap: *const cap_user_data) /
    { hdrp: cap_user_header, datap: cap_user_data } -> c_int for [x86_64: 126, aarch64: 91, riscv64: 91],
  chdir (path: *const c_char) / { path: PathBuf } -> c_int for [x86_64: 80, aarch64: 49, riscv64: 49],
  chmod (pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> c_int for [x86_64: 90],
  chown (pathname: *const c_char, owner: uid_t, group: gid_t)
    / { pathname: PathBuf, owner: uid_t, group: gid_t } -> c_int for [x86_64: 92],
  // chown32
  chroot (path: *const c_char) / { path: PathBuf } -> c_int for [x86_64: 161, aarch64: 51, riscv64: 51],
  clock_adjtime (clk_id: clockid_t, buf: *mut timex) / { clk_id: clockid_t, buf: timex } -> c_int for [x86_64: 305, aarch64: 266, riscv64: 266],
  // clock_adjtime64
  // TODO: sysexit:res should be Option<timespec>
  clock_getres (clk_id: clockid_t, res: *mut timespec) / { clk_id: clockid_t } -> c_int+res for [x86_64: 229, aarch64: 114, riscv64: 114],
  // clock_getres_time64
  // clock_gettime { clk_id: clockid_t, tp: mut* timespec } for [x86_64: 228, aarch64: 113, riscv64: 113],
  // clock_gettime64
  // clock_nanosleep { clockid: clockid_t, flags: c_int, request: const* timespec, remain: mut* timespec } for [x86_64: 230, aarch64: 115, riscv64: 115],
}
