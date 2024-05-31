#![allow(non_upper_case_globals)]

use std::path::PathBuf;
use std::{
  ffi::{c_int, CString},
  os::fd::RawFd,
};

use nix::libc::{
  c_char, c_long, c_uint, c_ulong, c_void, clockid_t, clone_args, epoll_event, gid_t, mode_t,
  off_t, pid_t, sigset_t, size_t, sockaddr, socklen_t, ssize_t, timespec, timex, uid_t, stat,
  statfs, timeval
};
use nix::sys::ptrace::AddressType;
use nix::unistd::Pid;
use tracer_syscalls_macros::gen_syscalls;

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, syscall_res_from_regs, PtraceRegisters},
  types::*,
  FromInspectingRegs, InspectError, SyscallNumber,
};

#[derive(Debug, Clone, Copy, PartialEq)]
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

pub type Unit = ();

gen_syscalls! {
  // _llseek (32bit)
  // _newselect
  accept(socketfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
    for [x86_64: 43, aarch64: 202, riscv64: 202],
  accept4(socketfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t, flags: c_int } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
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
  eventfd(initval: c_uint) / { initval: c_uint } -> c_int for [x86_64: 284],
  eventfd2(initval: c_uint, flags: c_int) / { initval: c_uint, flags: c_int } -> c_int for [x86_64: 290, aarch64: 19, riscv64: 19],
  // exec_with_loader, execv
  execve(filename: *const c_char, argv: *const *const c_char, envp: *const *const c_char) /
    { filename: PathBuf, argv: Option<Vec<CString>>, envp: Option<Vec<CString>> } -> c_int for [x86_64: 59, aarch64: 221, riscv64: 221],
  execveat(dirfd: RawFd, pathname: *const c_char, argv: *const *const c_char, envp: *const *const c_char, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, argv: Option<Vec<CString>>, envp: Option<Vec<CString>>, flags: c_int }
    -> c_int for [x86_64: 322, aarch64: 281, riscv64: 281],
  exit(status: c_int) / { status: c_int } -> Unit for [x86_64: 60, aarch64: 93, riscv64: 93],
  exit_group(status: c_int) / { status: c_int } -> Unit for [x86_64: 231, aarch64: 94, riscv64: 94],
  faccessat(dirfd: RawFd, pathname: *const c_char, mode: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: c_int } -> c_int for [x86_64: 269, aarch64: 48, riscv64: 48],
  faccessat2(dirfd: RawFd, pathname: *const c_char, mode: c_int, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: c_int, flags: c_int } -> c_int for [x86_64: 439, aarch64: 439, riscv64: 439],
  fadvise64(fd: RawFd, offset: off_t, len: size_t, advice: c_int) /
    { fd: RawFd, offset: off_t, len: size_t, advice: c_int } -> c_int for [x86_64: 221, aarch64: 223, riscv64: 223],
  // fadvise64_64(fd: RawFd, offset: off_t, len: off_t, advice: c_int) /
  //   { fd: RawFd, offset: off_t, len: off_t, advice: c_int } -> c_int for [],
  fallocate(fd: RawFd, mode: c_int, offset: off_t, len: off_t) /
    { fd: RawFd, mode: c_int, offset: off_t, len: off_t } -> c_int for [x86_64: 285, aarch64: 47, riscv64: 47],
  fanotify_init(flags: c_uint, event_f_flags: c_uint) /
    { flags: c_uint, event_f_flags: c_uint } -> c_int for [x86_64: 300, aarch64: 262, riscv64: 262],
  fanotify_mark(fanotify_fd: RawFd, flags: c_uint, mask: u64, dirfd: RawFd, pathname: *const c_char) /
    { fanotify_fd: RawFd, flags: c_uint, mask: u64, dirfd: RawFd, pathname: Option<PathBuf> } -> c_int for [x86_64: 301, aarch64: 263, riscv64: 263],
  fchdir(fd: RawFd) / { fd: RawFd } -> c_int for [x86_64: 81, aarch64: 50, riscv64: 50],
  fchmod(fd: RawFd, mode: mode_t) / { fd: RawFd, mode: mode_t } -> c_int for [x86_64: 91, aarch64: 52, riscv64: 52],
  fchmodat(dirfd: RawFd, pathname: *const c_char, mode: mode_t) /
    { dirfd: RawFd, pathname: PathBuf, mode: mode_t } -> c_int for [x86_64: 268, aarch64: 53, riscv64: 53],
  fchmodat2(dirfd: RawFd, pathname: *const c_char, mode: mode_t, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: mode_t, flags: c_int } -> c_int for [x86_64: 452, aarch64: 452, riscv64: 452],
  fchown(fd: RawFd, owner: uid_t, group: gid_t) / { fd: RawFd, owner: uid_t, group: gid_t } -> c_int for [x86_64: 93, aarch64: 55, riscv64: 55],
  // fchown32
  fchownat(dirfd: RawFd, pathname: *const c_char, owner: uid_t, group: gid_t, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, owner: uid_t, group: gid_t, flags: c_int } -> c_int for [x86_64: 260, aarch64: 54, riscv64: 54],
  fcntl(fd: RawFd, cmd: c_int, arg: usize) / { fd: RawFd, cmd: c_int, arg: usize } -> c_int for [x86_64: 72, aarch64: 25, riscv64: 25],
  // fcntl64
  fdatasync(fd: RawFd) / { fd: RawFd } -> c_int for [x86_64: 75, aarch64: 83, riscv64: 83],
  fgetxattr(fd: RawFd, name: *const c_char, value: *mut c_void, size: size_t) /
    { fd: RawFd, name: CString, value: CString, size: size_t } -> ssize_t for [x86_64: 193, aarch64: 10, riscv64: 10],
  finit_module(fd: RawFd, param_values: *const c_char, flags: c_int) /
    { fd: RawFd, param_values: CString, flags: c_int } -> c_int for [x86_64: 313, aarch64: 273, riscv64: 273],
  flistxattr(fd: RawFd, list: *mut c_char, size: size_t) /
    { fd: RawFd, list: Option<CString>, size: size_t } -> ssize_t for [x86_64: 194, aarch64: 11, riscv64: 11],
  flock(fd: RawFd, operation: c_int) / { fd: RawFd, operation: c_int } -> c_int for [x86_64: 73, aarch64: 32, riscv64: 32],
  fork() / {} -> pid_t for [x86_64: 57],
  fremovexattr(fd: RawFd, name: *const c_char) / { fd: RawFd, name: CString } -> c_int for [x86_64: 196, aarch64: 16, riscv64: 16],
  // fsconfig: https://go-review.googlesource.com/c/sys/+/484995 and https://lwn.net/Articles/766155/
  fsconfig(fd: RawFd, cmd: c_uint, key: *const c_char, value: *const c_char, aux: c_int) /
    { fd: RawFd, cmd: c_uint, key: CString, value: CString, aux: c_int } -> c_int for [x86_64: 431, aarch64: 431, riscv64: 431],
  fsetxattr(fd: RawFd, name: *const c_char, value: *const c_void, size: size_t, flags: c_int) /
    { fd: RawFd, name: CString, value: CString, size: size_t, flags: c_int } -> c_int for [x86_64: 190, aarch64: 7, riscv64: 7],
  // https://lwn.net/Articles/759499/ 
  fsmount(fd: RawFd, flags: c_uint, ms_flags: c_uint) /
    { fd: RawFd, flags: c_uint, ms_flags: c_uint } -> c_int for [x86_64: 432, aarch64: 432, riscv64: 432],
  fsopen(fsname: *const c_char, flags: c_uint) / { fsname: CString, flags: c_uint } -> c_int for [x86_64: 430, aarch64: 430, riscv64: 430],
  fspick(dirfd: RawFd, pathname: *const c_char, flags: c_uint) / { dirfd: RawFd, pathname: CString, flags: c_uint } -> c_int for [x86_64: 433, aarch64: 433, riscv64: 433],
  fstat(fd: RawFd, statbuf: *mut stat) / { fd: RawFd } -> c_int + { statbuf: stat } for [x86_64: 5, aarch64: 80, riscv64: 80],
  // fstat64, fstatat64
  fstatfs(fd: RawFd, buf: *mut statfs) / { fd: RawFd } -> c_int + { buf: statfs } for [x86_64: 138, aarch64: 44, riscv64: 44],
  // fstatfs64
  fsync(fd: RawFd) / { fd: RawFd } -> c_int for [x86_64: 74, aarch64: 82, riscv64: 82],
  ftruncate(fd: RawFd, length: off_t) / { fd: RawFd, length: off_t } -> c_int for [x86_64: 77, aarch64: 46, riscv64: 46],
  // ftruncate64
  // futex: val2 can be a pointer to timespec or a u32 value. val2, uaddr2 and val3 is optional for some ops. TODO: design a better rust interface
  futex(uaddr: *mut u32, futex_op: c_int, val: u32, val2: usize, uaddr2: *mut u32, val3: u32) /
    { uaddr: Result<u32, InspectError>, futex_op: c_int, val: u32, val2: usize, uaddr2: Result<u32, InspectError>, val3: u32 }
    -> c_long + { uaddr: Result<u32, InspectError>, uaddr2: Result<u32, InspectError> } for [x86_64: 202, aarch64: 98, riscv64: 98],
  // https://elixir.bootlin.com/linux/v6.9.3/source/include/linux/syscalls.h#L568
  // futex_requeue: waiters is always a two-element array of futex_waitv. TODO: design a better rust interface
  futex_requeue(waiters: *mut futex_waitv, flags: c_uint, nr_wake: c_int, nr_requeue: c_int) /
    { waiters: Vec<futex_waitv>, flags: c_uint, nr_wake: c_int, nr_requeue: c_int }
    -> c_long + { waiters: Vec<futex_waitv> } for [x86_64: 456, aarch64: 456, riscv64: 456],
  // futex_time64
  futex_wait(uaddr: *mut u32, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: *mut timespec, clockid: clockid_t) /
    { uaddr: Result<u32, InspectError>, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: timespec, clockid: clockid_t }
    -> c_long + { uaddr: Result<u32, InspectError> } for [x86_64: 455, aarch64: 455, riscv64: 455],
  futex_waitv(waiters: *mut futex_waitv, nr_futexes: c_uint, flags: c_uint, timeout: *mut timespec, clockid: clockid_t) /
    { waiters: Vec<futex_waitv>, nr_futexes: c_uint, flags: c_uint, timeout: timespec, clockid: clockid_t }
    -> c_long + { waiters: Vec<futex_waitv> } for [x86_64: 449, aarch64: 449, riscv64: 449],
  futex_wake(uaddr: *mut u32, mask: c_ulong, nr: c_int, flags: c_uint) /
    { uaddr: Result<u32, InspectError>, mask: c_ulong, nr: c_int, flags: c_uint }
    -> c_long + { uaddr: Result<u32, InspectError> } for [x86_64: 454, aarch64: 454, riscv64: 454],
  futimesat(dirfd: RawFd, pathname: *const c_char, times: *const timeval) /
    { dirfd: RawFd, pathname: PathBuf, times: [timeval;2] } -> c_int for [x86_64: 261],
  // get_mempolicy: nodemask: [c_ulong; (maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH]
  get_mempolicy(mode: *mut c_int, nodemask: *mut c_ulong, maxnode: c_ulong, addr: AddressType, flags: c_ulong) /
    { maxnode: c_ulong, addr: AddressType, flags: c_ulong } -> c_long +
    { mode: Result<Option<c_int>, InspectError>, nodemask: Option<Vec<c_ulong>> } for [x86_64: 239, aarch64: 236, riscv64: 236],
  get_robust_list(pid: pid_t, head_ptr: *mut *mut robust_list_head, len_ptr: *mut size_t) /
    { pid: pid_t, head_ptr: Result<AddressType, InspectError>, len_ptr: size_t } -> c_long for [x86_64: 274, aarch64: 100, riscv64: 100],
  get_thread_area(u_info: *mut user_desc) / { u_info: user_desc } -> c_int + { u_info: user_desc } for [x86_64: 211],
  getcpu(cpu: *mut c_uint, node: *mut c_uint) /
    { cpu: Result<Option<c_uint>, InspectError>, node: Result<Option<c_uint>, InspectError> } -> c_int for [x86_64: 309, aarch64: 168, riscv64: 168],
  getcwd(buf: *mut c_char, size: size_t) / { size: size_t } -> c_long + { buf: CString } for [x86_64: 79, aarch64: 17, riscv64: 17],
  getdents(fd: RawFd, dirp: *mut linux_dirent, count: c_uint) / { fd: RawFd, count: c_uint } -> c_int + { dirp: Vec<linux_dirent> } for [x86_64: 78],
  getdents64(fd: RawFd, dirp: *mut linux_dirent64, count: c_uint) / { fd: RawFd, count: c_uint } -> c_int + { dirp: Vec<linux_dirent64> } for [x86_64: 217, aarch64: 61, riscv64: 61],
}
