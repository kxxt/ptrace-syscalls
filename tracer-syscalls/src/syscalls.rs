#![allow(non_upper_case_globals)]

use std::path::PathBuf;
use std::{
  ffi::{c_int, CString},
  os::fd::RawFd,
};

use nix::libc::{
  c_char, c_uint, c_ulong, clockid_t, clone_args, epoll_event, gid_t, mode_t, off_t, pid_t, size_t,
  sockaddr, socklen_t, ssize_t, timespec, timex, uid_t, sigset_t
};
use nix::sys::ptrace::AddressType;
use nix::unistd::Pid;
use tracer_syscalls_macros::gen_syscalls;

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, PtraceRegisters},
  types::*,
  FromInspectingRegs, InspectError, SyscallNumber,
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
  // _llseek (32bit)
  // _newselect
  accept(socketfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int + { addr: sockaddr, addrlen: socklen_t }
    for [x86_64: 43, aarch64: 202, riscv64: 202],
  accept4(socketfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t, flags: c_int } -> c_int + { addr: sockaddr, addrlen: socklen_t }
    for [x86_64: 288, aarch64: 242, riscv64: 242],
  access(pathname: *const c_char, mode: c_int) / { pathname: PathBuf, mode: c_int } -> c_int for [x86_64: 21],
  acct(filename: *const c_char) / { filename: Option<PathBuf> } -> c_int for [x86_64: 163, aarch64: 89, riscv64: 89],
  add_key(r#type: *const c_char, description: *const c_char, payload: *const c_void, plen: size_t, keyring: key_serial_t ) /
    { r#type: CString, description: CString, payload: Vec<u8>, plen: size_t, keyring: key_serial_t }
    -> key_serial_t for [x86_64: 248, aarch64: 217, riscv64: 217],
  adjtimex(buf: *mut timex) / { buf: timex } -> c_int for [x86_64: 159, aarch64: 171, riscv64: 171],
  alarm(seconds: c_uint) / { seconds: c_uint } -> c_uint for [x86_64: 37],
  // arc_gettls, arc_settls, arc_usr_cmpxchg
  arch_prctl(code: c_int, addr: c_ulong) / { code: c_int, addr: c_ulong } -> c_int for [x86_64: 158], // TODO: addr can be a ptr
  // arm_fadvise64_64, atomic_barrier, atomic_barrier
  bind(socketfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int for [x86_64: 49, aarch64: 200, riscv64: 200],
  // TODO: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L1454 and https://www.man7.org/linux/man-pages/man2/bpf.2.html
  bpf(cmd: c_int, attr: *mut c_void, size: c_uint) /
    { cmd: c_int, attr: Vec<u8>, size: c_uint } -> c_int for [x86_64: 321, aarch64: 280, riscv64: 280],
  brk(addr: *mut c_void) / { addr: AddressType } -> c_int for [x86_64: 12, aarch64: 214, riscv64: 214],
  // cachectl, cacheflush
  // cachestat { fd: RawFd, cstat_range: cachestat_range, cstat: cachestat, flags: c_uint } // TODO: https://github.com/golang/go/issues/61917
  capget(hdrp: *mut cap_user_header, datap: *mut cap_user_data) / { } -> c_int +
    { hdrp: cap_user_header, datap: cap_user_data } for [x86_64: 125, aarch64: 90, riscv64: 90],
  capset(hdrp: *mut cap_user_header, datap: *const cap_user_data) /
    { hdrp: cap_user_header, datap: cap_user_data } -> c_int for [x86_64: 126, aarch64: 91, riscv64: 91],
  chdir(path: *const c_char) / { path: PathBuf } -> c_int for [x86_64: 80, aarch64: 49, riscv64: 49],
  chmod(pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> c_int for [x86_64: 90],
  chown(pathname: *const c_char, owner: uid_t, group: gid_t)
    / { pathname: PathBuf, owner: uid_t, group: gid_t } -> c_int for [x86_64: 92],
  // chown32
  chroot(path: *const c_char) / { path: PathBuf } -> c_int for [x86_64: 161, aarch64: 51, riscv64: 51],
  clock_adjtime(clk_id: clockid_t, buf: *mut timex) / { clk_id: clockid_t, buf: timex } -> c_int for [x86_64: 305, aarch64: 266, riscv64: 266],
  // clock_adjtime64
  // TODO: sysexit:res should be Option<timespec>
  clock_getres(clk_id: clockid_t, res: *mut timespec) / { clk_id: clockid_t }
    -> c_int + { res: timespec } for [x86_64: 229, aarch64: 114, riscv64: 114],
  // clock_getres_time64
  clock_gettime(clk_id: clockid_t, tp: *mut timespec) / { clk_id: clockid_t }
    -> c_int + { tp: timespec } for [x86_64: 228, aarch64: 113, riscv64: 113],
  // clock_gettime64
  clock_nanosleep(clockid: clockid_t, flags: c_int, request: *const timespec, remain: *mut timespec) /
  { clockid: clockid_t, flags: c_int, request: timespec } -> c_int + { remain: Option<timespec> }
    for [x86_64: 230, aarch64: 115, riscv64: 115],
  // clock_nanosleep_time64
  clock_settime(clk_id: clockid_t, tp: *const timespec) / { clk_id: clockid_t, tp: timespec } -> c_int
    for [x86_64: 227, aarch64: 112, riscv64: 112],
  // clock_settime64
  // clone, the arguments vary for different architectures.
  clone(flags: c_ulong, stack: AddressType, parent_tid: *mut pid_t, child_tid: *mut pid_t, tls: c_ulong) /
   { flags: c_ulong, stack: AddressType, tls: c_ulong } -> c_long +
   { parent_tid: Result<pid_t, InspectError>, child_tid: Result<pid_t, InspectError> } for [x86_64: 56],
  clone(flags: c_ulong, stack: AddressType, parent_tid: *mut pid_t, tls: c_ulong, child_tid: *mut pid_t) /
   { flags: c_ulong, stack: AddressType, tls: c_ulong } -> c_long +
   { parent_tid: Result<pid_t, InspectError>, child_tid: Result<pid_t, InspectError> } for [aarch64: 220, riscv64: 220],
  clone3(cl_args: *mut clone_args, size: size_t) / { cl_args: clone_args, size: size_t } -> c_int for [x86_64: 435, aarch64: 435, riscv64: 435],
  close(fd: RawFd) / { fd: RawFd } -> c_int for [x86_64: 3, aarch64: 57, riscv64: 57],
  close_range(first: c_uint, last: c_uint, flags: c_uint) / { first: c_uint, last: c_uint, flags: c_uint }
    -> c_int for [x86_64: 436, aarch64: 436, riscv64: 436],
  connect(sockfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { sockfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int for [x86_64: 42, aarch64: 203, riscv64: 203],
  copy_file_range(fd_in: RawFd, off_in: *mut off_t, fd_out: RawFd, off_out: *mut off_t, len: size_t, flags: c_uint) /
    { fd_in: RawFd, off_in: Result<off_t, InspectError>, fd_out: RawFd, off_out: Result<off_t, InspectError>, len: size_t, flags: c_uint }
    -> ssize_t + { off_in: Result<off_t, InspectError>, off_out: Result<off_t, InspectError> } for [x86_64: 326, aarch64: 285, riscv64: 285],
  creat(pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> c_int for [x86_64: 85],
  delete_module(name: *const c_char, flags: c_uint) / { name: CString, flags: c_uint } -> c_int for [x86_64: 176, aarch64: 106, riscv64: 106],
  // dipc
  dup(oldfd: RawFd) / { oldfd: RawFd } -> c_int for [x86_64: 32, aarch64: 23, riscv64: 23],
  dup2(oldfd: RawFd, newfd: RawFd) / { oldfd: RawFd, newfd: RawFd } -> c_int for [x86_64: 33, aarch64: 24, riscv64: 24],
  dup3(oldfd: RawFd, newfd: RawFd, flags: c_int) / { oldfd: RawFd, newfd: RawFd, flags: c_int } -> c_int for [x86_64: 292, aarch64: 24, riscv64: 24],
  epoll_create(size: c_int) / { size: c_int } -> c_int for [x86_64: 213],
  epoll_create1(flags: c_int) / { flags: c_int } -> c_int for [x86_64: 291, aarch64: 20, riscv64: 20],
  epoll_ctl(epfd: RawFd, op: c_int, fd: RawFd, event: *mut epoll_event) /
    { epfd: RawFd, op: c_int, fd: RawFd, event: epoll_event } -> c_int for [x86_64: 233, aarch64: 21, riscv64: 21],
  // TODO: epoll_ctl_old
  // epoll_ctl_old(epfd: RawFd, op: c_int, fd: RawFd, event: *mut epoll_event) /
  //   { epfd: RawFd, op: c_int, fd: RawFd, event: epoll_event } -> c_int for [x86_64: 214],
  epoll_pwait(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const sigset_t) /
    { epfd: RawFd, maxevents: c_int, timeout: c_int, sigmask: sigset_t }
    -> c_int + { events: Vec<epoll_event> } for [x86_64: 281, aarch64: 22, riscv64: 22],
  epoll_pwait2(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: *const timespec, sigmask: *const sigset_t) /
    { epfd: RawFd, maxevents: c_int, timeout: Option<timespec>, sigmask: sigset_t }
    -> c_int + { events: Vec<epoll_event> } for [x86_64: 441, aarch64: 441, riscv64: 441],
  epoll_wait(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int) /
    { epfd: RawFd, maxevents: c_int, timeout: c_int }
    -> c_int + { events: Vec<epoll_event> } for [x86_64: 232],
  // TODO: epoll_wait_old
  // epoll_wait_old(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int) /
  //   { epfd: RawFd, maxevents: c_int, timeout: c_int }
  //   -> c_int + { events: Vec<epoll_event> } for [x86_64: 215],
}
