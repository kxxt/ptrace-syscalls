#![allow(non_upper_case_globals)]

use std::path::PathBuf;
use std::{
  ffi::{c_int, CString},
  os::fd::RawFd,
};

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, syscall_res_from_regs, PtraceRegisters},
  types::*,
  FromInspectingRegs, InspectError, SyscallNumber,
};
use crate::{SyscallGroups, SyscallGroupsGetter};
use enumflags2::BitFlags;
use nix::libc::{
  c_char, c_long, c_uchar, c_uint, c_ulong, c_void, clockid_t, clone_args, dev_t, epoll_event,
  gid_t, id_t, iocb, itimerspec, itimerval, key_t, mode_t, mq_attr, mqd_t, msqid_ds, nfds_t, off_t,
  open_how, pid_t, pollfd, rlimit, rusage, sigevent, siginfo_t, sigset_t, size_t, sockaddr,
  socklen_t, ssize_t, stat, statfs, timespec, timeval, timex, uid_t, loff_t, iovec, rlimit64, fd_set
};
use nix::sys::ptrace::AddressType;
use nix::unistd::Pid;
use tracer_syscalls_macros::gen_syscalls;

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

impl SyscallGroupsGetter for UnknownArgs {
  fn syscall_groups(&self) -> BitFlags<SyscallGroups> {
    BitFlags::empty()
  }
}

pub type Unit = ();

gen_syscalls! {
  // _llseek (32bit)
  // _newselect
  accept(socketfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: Result<socklen_t, InspectError> } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
    ~ [Network] for [x86_64: 43, aarch64: 202, riscv64: 202],
  accept4(socketfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) /
    { socketfd: RawFd, addr: sockaddr, addrlen: Result<socklen_t, InspectError>, flags: c_int } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
    ~ [Network] for [x86_64: 288, aarch64: 242, riscv64: 242],
  access(pathname: *const c_char, mode: c_int) / { pathname: PathBuf, mode: c_int } -> c_int ~ [File] for [x86_64: 21],
  acct(filename: *const c_char) / { filename: Option<PathBuf> } -> c_int ~ [File] for [x86_64: 163, aarch64: 89, riscv64: 89],
  add_key(r#type: *const c_char, description: *const c_char, payload: *const c_void, plen: size_t, keyring: key_serial_t ) /
    { r#type: CString, description: CString, payload: Vec<u8>, plen: size_t, keyring: key_serial_t }
    -> key_serial_t ~ [] for [x86_64: 248, aarch64: 217, riscv64: 217],
  adjtimex(buf: *mut timex) / { buf: timex } -> c_int ~ [Clock] for [x86_64: 159, aarch64: 171, riscv64: 171],
  alarm(seconds: c_uint) / { seconds: c_uint } -> c_uint ~ [] for [x86_64: 37],
  // arc_gettls, arc_settls, arc_usr_cmpxchg
  arch_prctl(code: c_int, addr: c_ulong) / { code: c_int, addr: c_ulong } -> c_int ~ [] for [x86_64: 158], // TODO: addr can be a ptr
  // arm_fadvise64_64, atomic_barrier, atomic_barrier
  bind(socketfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { socketfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int ~ [Network] for [x86_64: 49, aarch64: 200, riscv64: 200],
  // TODO: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L1454 and https://www.man7.org/linux/man-pages/man2/bpf.2.html
  bpf(cmd: c_int, attr: *mut c_void, size: c_uint) /
    { cmd: c_int, attr: Vec<u8>, size: c_uint } -> c_int ~ [Desc] for [x86_64: 321, aarch64: 280, riscv64: 280],
  brk(addr: *mut c_void) / { addr: AddressType } -> c_int ~ [Memory] for [x86_64: 12, aarch64: 214, riscv64: 214],
  // cachectl, cacheflush
  // cachestat { fd: RawFd, cstat_range: cachestat_range, cstat: cachestat, flags: c_uint } ~ [Desc] // TODO: https://github.com/golang/go/issues/61917
  capget(hdrp: *mut cap_user_header, datap: *mut cap_user_data) / { } -> c_int +
    { hdrp: cap_user_header, datap: cap_user_data } ~ [Creds] for [x86_64: 125, aarch64: 90, riscv64: 90],
  capset(hdrp: *mut cap_user_header, datap: *const cap_user_data) /
    { hdrp: cap_user_header, datap: cap_user_data } -> c_int ~ [Creds] for [x86_64: 126, aarch64: 91, riscv64: 91],
  chdir(path: *const c_char) / { path: PathBuf } -> c_int ~ [File] for [x86_64: 80, aarch64: 49, riscv64: 49],
  chmod(pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> c_int ~ [File] for [x86_64: 90],
  chown(pathname: *const c_char, owner: uid_t, group: gid_t)
    / { pathname: PathBuf, owner: uid_t, group: gid_t } -> c_int ~ [File] for [x86_64: 92],
  // chown32
  chroot(path: *const c_char) / { path: PathBuf } -> c_int ~ [File] for [x86_64: 161, aarch64: 51, riscv64: 51],
  clock_adjtime(clk_id: clockid_t, buf: *mut timex) / { clk_id: clockid_t, buf: timex } -> c_int ~ [Clock] for [x86_64: 305, aarch64: 266, riscv64: 266],
  // clock_adjtime64
  // TODO: sysexit:res should be Option<timespec>
  clock_getres(clk_id: clockid_t, res: *mut timespec) / { clk_id: clockid_t }
    -> c_int + { res: timespec } ~ [Clock] for [x86_64: 229, aarch64: 114, riscv64: 114],
  // clock_getres_time64
  clock_gettime(clk_id: clockid_t, tp: *mut timespec) / { clk_id: clockid_t }
    -> c_int + { tp: timespec } ~ [Clock] for [x86_64: 228, aarch64: 113, riscv64: 113],
  // clock_gettime64
  clock_nanosleep(clockid: clockid_t, flags: c_int, request: *const timespec, remain: *mut timespec) /
  { clockid: clockid_t, flags: c_int, request: timespec } -> c_int + { remain: Option<timespec> }
    ~ [] for [x86_64: 230, aarch64: 115, riscv64: 115],
  // clock_nanosleep_time64
  clock_settime(clk_id: clockid_t, tp: *const timespec) / { clk_id: clockid_t, tp: timespec } -> c_int
    ~ [Clock] for [x86_64: 227, aarch64: 112, riscv64: 112],
  // clock_settime64
  // clone, the arguments vary for different architectures.
  clone(flags: c_ulong, stack: AddressType, parent_tid: *mut pid_t, child_tid: *mut pid_t, tls: c_ulong) /
   { flags: c_ulong, stack: AddressType, tls: c_ulong } -> c_long +
   { parent_tid: Result<pid_t, InspectError>, child_tid: Result<pid_t, InspectError> } ~ [Process] for [x86_64: 56],
  clone(flags: c_ulong, stack: AddressType, parent_tid: *mut pid_t, tls: c_ulong, child_tid: *mut pid_t) /
   { flags: c_ulong, stack: AddressType, tls: c_ulong } -> c_long +
   { parent_tid: Result<pid_t, InspectError>, child_tid: Result<pid_t, InspectError> } ~ [Process] for [aarch64: 220, riscv64: 220],
  clone3(cl_args: *mut clone_args, size: size_t) / { cl_args: clone_args, size: size_t } -> c_int ~ [Process] for [x86_64: 435, aarch64: 435, riscv64: 435],
  close(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 3, aarch64: 57, riscv64: 57],
  close_range(first: c_uint, last: c_uint, flags: c_uint) / { first: c_uint, last: c_uint, flags: c_uint }
    -> c_int ~ [] for [x86_64: 436, aarch64: 436, riscv64: 436],
  connect(sockfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { sockfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int ~ [Network] for [x86_64: 42, aarch64: 203, riscv64: 203],
  copy_file_range(fd_in: RawFd, off_in: *mut off_t, fd_out: RawFd, off_out: *mut off_t, len: size_t, flags: c_uint) /
    { fd_in: RawFd, off_in: Result<off_t, InspectError>, fd_out: RawFd, off_out: Result<off_t, InspectError>, len: size_t, flags: c_uint }
    -> ssize_t + { off_in: Result<off_t, InspectError>, off_out: Result<off_t, InspectError> } ~ [Desc] for [x86_64: 326, aarch64: 285, riscv64: 285],
  creat(pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> RawFd ~ [Desc, File] for [x86_64: 85],
  delete_module(name: *const c_char, flags: c_uint) / { name: CString, flags: c_uint } -> c_int ~ [] for [x86_64: 176, aarch64: 106, riscv64: 106],
  // dipc
  dup(oldfd: RawFd) / { oldfd: RawFd } -> c_int ~ [Desc] for [x86_64: 32, aarch64: 23, riscv64: 23],
  dup2(oldfd: RawFd, newfd: RawFd) / { oldfd: RawFd, newfd: RawFd } -> c_int ~ [Desc] for [x86_64: 33, aarch64: 24, riscv64: 24],
  dup3(oldfd: RawFd, newfd: RawFd, flags: c_int) / { oldfd: RawFd, newfd: RawFd, flags: c_int } -> c_int ~ [Desc] for [x86_64: 292, aarch64: 24, riscv64: 24],
  epoll_create(size: c_int) / { size: c_int } -> c_int ~ [Desc] for [x86_64: 213],
  epoll_create1(flags: c_int) / { flags: c_int } -> c_int ~ [Desc] for [x86_64: 291, aarch64: 20, riscv64: 20],
  epoll_ctl(epfd: RawFd, op: c_int, fd: RawFd, event: *mut epoll_event) /
    { epfd: RawFd, op: c_int, fd: RawFd, event: epoll_event } -> c_int ~ [Desc] for [x86_64: 233, aarch64: 21, riscv64: 21],
  // TODO: epoll_ctl_old
  // epoll_ctl_old(epfd: RawFd, op: c_int, fd: RawFd, event: *mut epoll_event) /
  //   { epfd: RawFd, op: c_int, fd: RawFd, event: epoll_event } -> c_int for [x86_64: 214],
  epoll_pwait(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const sigset_t) /
    { epfd: RawFd, maxevents: c_int, timeout: c_int, sigmask: sigset_t }
    -> c_int + { events: Vec<epoll_event> } ~ [Desc] for [x86_64: 281, aarch64: 22, riscv64: 22],
  epoll_pwait2(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: *const timespec, sigmask: *const sigset_t) /
    { epfd: RawFd, maxevents: c_int, timeout: Option<timespec>, sigmask: sigset_t }
    -> c_int + { events: Vec<epoll_event> } ~ [Desc] for [x86_64: 441, aarch64: 441, riscv64: 441],
  epoll_wait(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int) /
    { epfd: RawFd, maxevents: c_int, timeout: c_int }
    -> c_int + { events: Vec<epoll_event> } ~ [Desc] for [x86_64: 232],
  // TODO: epoll_wait_old
  // epoll_wait_old(epfd: RawFd, events: *mut epoll_event, maxevents: c_int, timeout: c_int) /
  //   { epfd: RawFd, maxevents: c_int, timeout: c_int }
  //   -> c_int + { events: Vec<epoll_event> } for [x86_64: 215],
  eventfd(initval: c_uint) / { initval: c_uint } -> c_int ~ [Desc] for [x86_64: 284],
  eventfd2(initval: c_uint, flags: c_int) / { initval: c_uint, flags: c_int } -> c_int ~ [Desc] for [x86_64: 290, aarch64: 19, riscv64: 19],
  // exec_with_loader, execv
  execve(filename: *const c_char, argv: *const *const c_char, envp: *const *const c_char) /
    { filename: PathBuf, argv: Option<Vec<CString>>, envp: Option<Vec<CString>> } -> c_int
    ~ [File, Process] for [x86_64: 59, aarch64: 221, riscv64: 221],
  execveat(dirfd: RawFd, pathname: *const c_char, argv: *const *const c_char, envp: *const *const c_char, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, argv: Option<Vec<CString>>, envp: Option<Vec<CString>>, flags: c_int }
    -> c_int ~ [Desc, File, Process] for [x86_64: 322, aarch64: 281, riscv64: 281],
  exit(status: c_int) / { status: c_int } -> Unit ~ [Process] for [x86_64: 60, aarch64: 93, riscv64: 93],
  exit_group(status: c_int) / { status: c_int } -> Unit ~ [Process] for [x86_64: 231, aarch64: 94, riscv64: 94],
  faccessat(dirfd: RawFd, pathname: *const c_char, mode: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: c_int } -> c_int ~ [Desc, File] for [x86_64: 269, aarch64: 48, riscv64: 48],
  faccessat2(dirfd: RawFd, pathname: *const c_char, mode: c_int, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: c_int, flags: c_int } -> c_int ~ [Desc, File] for [x86_64: 439, aarch64: 439, riscv64: 439],
  fadvise64(fd: RawFd, offset: off_t, len: size_t, advice: c_int) /
    { fd: RawFd, offset: off_t, len: size_t, advice: c_int } -> c_int ~ [Desc] for [x86_64: 221, aarch64: 223, riscv64: 223],
  // fadvise64_64(fd: RawFd, offset: off_t, len: off_t, advice: c_int) /
  //   { fd: RawFd, offset: off_t, len: off_t, advice: c_int } -> c_int ~ [Desc] for [],
  fallocate(fd: RawFd, mode: c_int, offset: off_t, len: off_t) /
    { fd: RawFd, mode: c_int, offset: off_t, len: off_t } -> c_int ~ [Desc] for [x86_64: 285, aarch64: 47, riscv64: 47],
  fanotify_init(flags: c_uint, event_f_flags: c_uint) /
    { flags: c_uint, event_f_flags: c_uint } -> c_int ~ [Desc] for [x86_64: 300, aarch64: 262, riscv64: 262],
  fanotify_mark(fanotify_fd: RawFd, flags: c_uint, mask: u64, dirfd: RawFd, pathname: *const c_char) /
    { fanotify_fd: RawFd, flags: c_uint, mask: u64, dirfd: RawFd, pathname: Option<PathBuf> } -> c_int ~ [Desc, File] for [x86_64: 301, aarch64: 263, riscv64: 263],
  fchdir(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 81, aarch64: 50, riscv64: 50],
  fchmod(fd: RawFd, mode: mode_t) / { fd: RawFd, mode: mode_t } -> c_int ~ [Desc] for [x86_64: 91, aarch64: 52, riscv64: 52],
  fchmodat(dirfd: RawFd, pathname: *const c_char, mode: mode_t) /
    { dirfd: RawFd, pathname: PathBuf, mode: mode_t } -> c_int ~ [Desc, File] for [x86_64: 268, aarch64: 53, riscv64: 53],
  fchmodat2(dirfd: RawFd, pathname: *const c_char, mode: mode_t, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, mode: mode_t, flags: c_int } -> c_int ~ [Desc, File] for [x86_64: 452, aarch64: 452, riscv64: 452],
  fchown(fd: RawFd, owner: uid_t, group: gid_t) / { fd: RawFd, owner: uid_t, group: gid_t } -> c_int ~ [Desc] for [x86_64: 93, aarch64: 55, riscv64: 55],
  // fchown32
  fchownat(dirfd: RawFd, pathname: *const c_char, owner: uid_t, group: gid_t, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, owner: uid_t, group: gid_t, flags: c_int } -> c_int ~ [Desc, File] for [x86_64: 260, aarch64: 54, riscv64: 54],
  fcntl(fd: RawFd, cmd: c_int, arg: usize) / { fd: RawFd, cmd: c_int, arg: usize } -> c_int ~ [Desc] for [x86_64: 72, aarch64: 25, riscv64: 25],
  // fcntl64
  fdatasync(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 75, aarch64: 83, riscv64: 83],
  fgetxattr(fd: RawFd, name: *const c_char, value: *mut c_void, size: size_t) /
    { fd: RawFd, name: CString, value: CString, size: size_t } -> ssize_t ~ [Desc] for [x86_64: 193, aarch64: 10, riscv64: 10],
  finit_module(fd: RawFd, param_values: *const c_char, flags: c_int) /
    { fd: RawFd, param_values: CString, flags: c_int } -> c_int ~ [Desc] for [x86_64: 313, aarch64: 273, riscv64: 273],
  flistxattr(fd: RawFd, list: *mut c_char, size: size_t) /
    { fd: RawFd, list: Option<CString>, size: size_t } -> ssize_t ~ [Desc] for [x86_64: 196, aarch64: 13, riscv64: 13],
  flock(fd: RawFd, operation: c_int) / { fd: RawFd, operation: c_int } -> c_int ~ [Desc] for [x86_64: 73, aarch64: 32, riscv64: 32],
  fork() / {} -> pid_t ~ [Process] for [x86_64: 57],
  fremovexattr(fd: RawFd, name: *const c_char) / { fd: RawFd, name: CString } -> c_int ~ [Desc] for [x86_64: 196, aarch64: 16, riscv64: 16],
  // fsconfig: https://go-review.googlesource.com/c/sys/+/484995 and https://lwn.net/Articles/766155/
  fsconfig(fd: RawFd, cmd: c_uint, key: *const c_char, value: *const c_char, aux: c_int) /
    { fd: RawFd, cmd: c_uint, key: CString, value: CString, aux: c_int } -> c_int ~ [Desc, File] for [x86_64: 431, aarch64: 431, riscv64: 431],
  fsetxattr(fd: RawFd, name: *const c_char, value: *const c_void, size: size_t, flags: c_int) /
    { fd: RawFd, name: CString, value: CString, size: size_t, flags: c_int } -> c_int ~ [Desc] for [x86_64: 190, aarch64: 7, riscv64: 7],
  // https://lwn.net/Articles/759499/
  fsmount(fd: RawFd, flags: c_uint, ms_flags: c_uint) /
    { fd: RawFd, flags: c_uint, ms_flags: c_uint } -> c_int ~ [Desc] for [x86_64: 432, aarch64: 432, riscv64: 432],
  fsopen(fsname: *const c_char, flags: c_uint) / { fsname: CString, flags: c_uint } -> c_int ~ [Desc] for [x86_64: 430, aarch64: 430, riscv64: 430],
  fspick(dirfd: RawFd, pathname: *const c_char, flags: c_uint) / { dirfd: RawFd, pathname: CString, flags: c_uint } -> c_int
    ~ [Desc, File] for [x86_64: 433, aarch64: 433, riscv64: 433],
  fstat(fd: RawFd, statbuf: *mut stat) / { fd: RawFd } -> c_int + { statbuf: stat } ~ [Desc, FStat, StatLike] for [x86_64: 5, aarch64: 80, riscv64: 80],
  // fstat64, fstatat64
  fstatfs(fd: RawFd, buf: *mut statfs) / { fd: RawFd } -> c_int + { buf: statfs } ~ [Desc, FStatFs, StatFsLike] for [x86_64: 138, aarch64: 44, riscv64: 44],
  // fstatfs64
  fsync(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 74, aarch64: 82, riscv64: 82],
  ftruncate(fd: RawFd, length: off_t) / { fd: RawFd, length: off_t } -> c_int ~ [Desc] for [x86_64: 77, aarch64: 46, riscv64: 46],
  // ftruncate64
  // futex: val2 can be a pointer to timespec or a u32 value. val2, uaddr2 and val3 is optional for some ops. TODO: design a better rust interface
  futex(uaddr: *mut u32, futex_op: c_int, val: u32, val2: usize, uaddr2: *mut u32, val3: u32) /
    { uaddr: Result<u32, InspectError>, futex_op: c_int, val: u32, val2: usize, uaddr2: Result<u32, InspectError>, val3: u32 }
    -> c_long + { uaddr: Result<u32, InspectError>, uaddr2: Result<u32, InspectError> } ~ [] for [x86_64: 202, aarch64: 98, riscv64: 98],
  // https://elixir.bootlin.com/linux/v6.9.3/source/include/linux/syscalls.h#L568
  // futex_requeue: waiters is always a two-element array of futex_waitv. TODO: design a better rust interface
  futex_requeue(waiters: *mut futex_waitv, flags: c_uint, nr_wake: c_int, nr_requeue: c_int) /
    { waiters: Vec<futex_waitv>, flags: c_uint, nr_wake: c_int, nr_requeue: c_int }
    -> c_long + { waiters: Vec<futex_waitv> } ~ [] for [x86_64: 456, aarch64: 456, riscv64: 456],
  // futex_time64
  futex_wait(uaddr: *mut u32, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: *mut timespec, clockid: clockid_t) /
    { uaddr: Result<u32, InspectError>, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: timespec, clockid: clockid_t }
    -> c_long + { uaddr: Result<u32, InspectError> } ~ [] for [x86_64: 455, aarch64: 455, riscv64: 455],
  futex_waitv(waiters: *mut futex_waitv, nr_futexes: c_uint, flags: c_uint, timeout: *mut timespec, clockid: clockid_t) /
    { waiters: Vec<futex_waitv>, nr_futexes: c_uint, flags: c_uint, timeout: timespec, clockid: clockid_t }
    -> c_long + { waiters: Vec<futex_waitv> } ~ [] for [x86_64: 449, aarch64: 449, riscv64: 449],
  futex_wake(uaddr: *mut u32, mask: c_ulong, nr: c_int, flags: c_uint) /
    { uaddr: Result<u32, InspectError>, mask: c_ulong, nr: c_int, flags: c_uint }
    -> c_long + { uaddr: Result<u32, InspectError> } ~ [] for [x86_64: 454, aarch64: 454, riscv64: 454],
  futimesat(dirfd: RawFd, pathname: *const c_char, times: *const timeval) /
    { dirfd: RawFd, pathname: PathBuf, times: [timeval;2] } -> c_int ~ [Desc, File] for [x86_64: 261],
  // get_mempolicy: nodemask: [c_ulong; (maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH]
  get_mempolicy(mode: *mut c_int, nodemask: *mut c_ulong, maxnode: c_ulong, addr: AddressType, flags: c_ulong) /
    { maxnode: c_ulong, addr: AddressType, flags: c_ulong } -> c_long +
    { mode: Result<Option<c_int>, InspectError>, nodemask: Option<Vec<c_ulong>> } ~ [Memory] for [x86_64: 239, aarch64: 236, riscv64: 236],
  get_robust_list(pid: pid_t, head_ptr: *mut *mut robust_list_head, len_ptr: *mut size_t) /
    { pid: pid_t, head_ptr: Result<AddressType, InspectError>, len_ptr: size_t } -> c_long ~ [] for [x86_64: 274, aarch64: 100, riscv64: 100],
  get_thread_area(u_info: *mut user_desc) / { u_info: user_desc } -> c_int + { u_info: user_desc } ~ [] for [x86_64: 211],
  getcpu(cpu: *mut c_uint, node: *mut c_uint) /
    { cpu: Result<Option<c_uint>, InspectError>, node: Result<Option<c_uint>, InspectError> } -> c_int ~ [] for [x86_64: 309, aarch64: 168, riscv64: 168],
  getcwd(buf: *mut c_char, size: size_t) / { size: size_t } -> c_long + { buf: CString } ~ [File] for [x86_64: 79, aarch64: 17, riscv64: 17],
  getdents(fd: RawFd, dirp: *mut linux_dirent, count: c_uint) / { fd: RawFd, count: c_uint } -> c_int + { dirp: Vec<linux_dirent> } ~ [Desc] for [x86_64: 78],
  getdents64(fd: RawFd, dirp: *mut linux_dirent64, count: c_uint) / { fd: RawFd, count: c_uint } -> c_int + { dirp: Vec<linux_dirent64> }
    ~ [Desc] for [x86_64: 217, aarch64: 61, riscv64: 61],
  // getdomainname
  // getdtablesize
  getegid() / {} -> gid_t ~ [Creds, Pure] for [x86_64: 108, aarch64: 177, riscv64: 177],
  // getegid32
  geteuid() / {} -> uid_t ~ [Creds, Pure] for [x86_64: 107, aarch64: 175, riscv64: 175],
  // geteuid32
  getgid() / {} -> gid_t ~ [Creds, Pure] for [x86_64: 104, aarch64: 176, riscv64: 176],
  // getgid32
  getgroups(size: c_int, list: *mut gid_t) / { size: c_int } -> c_int + { list: Vec<gid_t> } ~ [Creds] for [x86_64: 115, aarch64: 158, riscv64: 158],
  // getgroups32
  // gethostname
  getitimer(which: c_int, value: *mut itimerval) / { which: c_int } -> c_int + { value: itimerval } ~ [] for [x86_64: 36, aarch64: 102, riscv64: 102],
  // getpagesize
  getpeername(sockfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { sockfd: RawFd, addr: sockaddr, addrlen: Result<socklen_t, InspectError> } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
    ~ [Network] for [x86_64: 52, aarch64: 205, riscv64: 205],
  getpgid(pid: pid_t) / { pid: pid_t } -> pid_t ~ [] for [x86_64: 121, aarch64: 155, riscv64: 155],
  getpgrp() / {} -> pid_t ~ [Pure] for [x86_64: 111],
  getpid() / {} -> pid_t ~ [Pure] for [x86_64: 39, aarch64: 172, riscv64: 172],
  getppid() / {} -> pid_t ~ [Pure] for [x86_64: 110, aarch64: 173, riscv64: 173],
  getpriority(which: c_int, who: id_t) / { which: c_int, who: id_t } -> c_int ~ [] for [x86_64: 140, aarch64: 141, riscv64: 141],
  getrandom(buf: *mut c_void, buflen: size_t, flags: c_uint) / { buflen: size_t, flags: c_uint } -> ssize_t + { buf: Vec<u8> }
    ~ [] for [x86_64: 318, aarch64: 278, riscv64: 278],
  getresgid(rgid: *mut gid_t, egid: *mut gid_t, sgid: *mut gid_t) / {}
    -> c_int + { rgid: Result<gid_t, InspectError>, egid: Result<gid_t, InspectError>, sgid: Result<gid_t, InspectError> }
    ~ [Creds] for [x86_64: 120, aarch64: 150, riscv64: 150],
  // getresgid32
  getresuid(ruid: *mut uid_t, euid: *mut uid_t, suid: *mut uid_t) / {}
    -> c_int + { ruid: Result<uid_t, InspectError>, euid: Result<uid_t, InspectError>, suid: Result<uid_t, InspectError> }
    ~ [Creds] for [x86_64: 118, aarch64: 148, riscv64: 148],
  // getresuid32
  getrlimit(resource: c_int, rlim: *mut rlimit) / { resource: c_int } -> c_int + { rlim: rlimit } ~ [] for [x86_64: 97, aarch64: 163, riscv64: 163],
  getrusage(who: c_int, usage: *mut rusage) / { who: c_int } -> c_int + { usage: rusage } ~ [] for [x86_64: 98, aarch64: 165, riscv64: 165],
  getsid(pid: pid_t) / { pid: pid_t } -> pid_t ~ [] for [x86_64: 124, aarch64: 156, riscv64: 156],
  getsockname(sockfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { sockfd: RawFd, addrlen: Result<socklen_t, InspectError> } -> c_int + { addr: sockaddr, addrlen: Result<socklen_t, InspectError> }
    ~ [Network] for [x86_64: 51, aarch64: 204, riscv64: 204],
  getsockopt(sockfd: RawFd, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut socklen_t) /
    { sockfd: RawFd, level: c_int, optname: c_int, optlen: Result<socklen_t, InspectError> }
    -> c_int + { optval: Vec<u8>, optlen: Result<socklen_t, InspectError> }
    ~ [Network] for [x86_64: 55, aarch64: 209, riscv64: 209],
  gettid() / {} -> pid_t ~ [Pure] for [x86_64: 186, aarch64: 178, riscv64: 178],
  gettimeofday(tv: *mut timeval, tz: *mut timezone) / {} -> c_int + { tv: timeval, tz: Option<timezone> } ~ [Clock] for [x86_64: 96, aarch64: 169, riscv64: 169],
  getuid() / {} -> uid_t ~ [Creds, Pure] for [x86_64: 102, aarch64: 174, riscv64: 174],
  // getuid32
  getxattr(pathname: *const c_char, name: *const c_char, value: *mut c_void, size: size_t) /
    { pathname: PathBuf, name: CString, size: size_t } -> ssize_t + { value: Vec<u8> } ~ [File] for [x86_64: 191, aarch64: 8, riscv64: 8],
  // getxgid
  // getxpid
  // getxuid
  init_module(module_image: *mut c_void, len: c_ulong, param_values: *const c_char) /
    { module_image: Vec<u8>, len: c_ulong, param_values: CString } -> c_int ~ [] for [x86_64: 175, aarch64: 105, riscv64: 105],
  inotify_add_watch(fd: RawFd, pathname: *const c_char, mask: u32) /
    { fd: RawFd, pathname: PathBuf, mask: u32 } -> c_int ~ [Desc, File] for [x86_64: 254, aarch64: 27, riscv64: 27],
  inotify_init() / {} -> RawFd ~ [Desc] for [x86_64: 253],
  inotify_init1(flags: c_int) / { flags: c_int } -> RawFd ~ [Desc] for [x86_64: 294, aarch64: 26, riscv64: 26],
  inotify_rm_watch(fd: RawFd, wd: c_int) / { fd: RawFd, wd: c_int } -> c_int ~ [Desc] for [x86_64: 255, aarch64: 28, riscv64: 28],
  io_cancel(ctx_id: aio_context_t, iocb: *mut iocb, result: *mut io_event) /
    { ctx_id: aio_context_t, iocb: iocb } -> c_int + { result: io_event } ~ [] for [x86_64: 210, aarch64: 3, riscv64: 3],
  // TODO: strace doesn't have io_destory?
  io_destory(ctx_id: aio_context_t) / { ctx_id: aio_context_t } -> c_int ~ [] for [x86_64: 207, aarch64: 1, riscv64: 1],

  io_getevents(ctx_id: aio_context_t, min_nr: c_long, nr: c_long, events: *mut io_event, timeout: *mut timespec) /
    { ctx_id: aio_context_t, min_nr: c_long, nr: c_long, timeout: Option<timespec> }
    -> c_int + { events: Vec<io_event> } ~ [] for [x86_64: 208, aarch64: 4, riscv64: 4],
  io_pgetevents(ctx_id: aio_context_t, min_nr: c_long, nr: c_long, events: *mut io_event, timeout: *mut timespec, sig: *const __aio_sigset) /
    { ctx_id: aio_context_t, min_nr: c_long, nr: c_long, timeout: Option<timespec>, sig: __aio_sigset }
    -> c_int + { events: Vec<io_event> } ~ [] for [x86_64: 333, aarch64: 292, riscv64: 292],
  // io_pgetevents_time64
  io_setup(nr_events: c_ulong, ctx_idp: *mut aio_context_t) / { nr_events: c_ulong }
    -> c_int + { ctx_idp: aio_context_t } ~ [Memory] for [x86_64: 206, aarch64: 0, riscv64: 0],
  // io_submit: iocbpp is an array of iocb pointers. TODO: how to handle it?
  io_submit(ctx_id: aio_context_t, nr: c_long, iocbpp: *mut *mut iocb) /
    { ctx_id: aio_context_t, nr: c_long, iocbpp: Vec<AddressType> } -> c_int ~ [] for [x86_64: 209, aarch64: 2, riscv64: 2],
  // io_uring_enter: arg can be a sigset_t ptr or io_uring_getevents_arg ptr depending on the flags
  io_uring_enter(fd: c_uint, to_submit: c_uint, min_complete: c_uint, flags: c_uint, arg: AddressType, argsz: size_t) /
    { fd: c_uint, to_submit: c_uint, min_complete: c_uint, flags: c_uint, arg: Vec<u8>, argsz: size_t }
    -> c_int ~ [Desc, File] for [x86_64: 426, aarch64: 426, riscv64: 426],
  // arg can point to a lot of different struct (array) depending on the op
  io_uring_register(fd: c_uint, op: c_uint, arg: AddressType, nr_args: c_uint) /
    { fd: c_uint, op: c_uint, arg: AddressType, nr_args: c_uint } -> c_int ~ [Desc, Memory] for [x86_64: 427, aarch64: 427, riscv64: 427],
  io_uring_setup(entries: u32, p: *mut io_uring_params) /
    { entries: c_uint, p: io_uring_params } -> c_int + { p: io_uring_params } ~ [Desc] for [x86_64: 425, aarch64: 425, riscv64: 425],
  ioctl(fd: RawFd, request: c_ulong, argp: AddressType) / { fd: RawFd, request: c_ulong, argp: AddressType }
    -> c_int ~ [Desc] for [x86_64: 16, aarch64: 29, riscv64: 29],
  ioperm(from: c_ulong, num: c_ulong, turn_on: c_int) / { from: c_ulong, num: c_ulong, turn_on: c_int } -> c_int ~ [] for [x86_64: 173],
  iopl(level: c_int) / { level: c_int } -> c_int ~ [] for [x86_64: 172],
  ioprio_get(which: c_int, who: c_int) / { which: c_int, who: c_int } -> c_int ~ [] for [x86_64: 252, aarch64: 31, riscv64: 31],
  ioprio_set(which: c_int, who: c_int, ioprio: c_int) / { which: c_int, who: c_int, ioprio: c_int } -> c_int ~ [] for [x86_64: 251, aarch64: 30, riscv64: 30],
  // ipc
  kcmp(pid1: pid_t, pid2: pid_t, r#type: c_int, idx1: c_ulong, idx2: c_ulong) /
    { pid1: pid_t, pid2: pid_t, r#type: c_int, idx1: c_ulong, idx2: c_ulong } -> c_int ~ [] for [x86_64: 312, aarch64: 272, riscv64: 272],
  // kern_features
  kexec_file_load(kernel_fd: RawFd, initrd_fd: RawFd, cmdline_len: c_ulong, cmdline: *const c_char, flags: c_ulong) /
    { kernel_fd: RawFd, initrd_fd: RawFd, cmdline_len: c_ulong, cmdline: CString, flags: c_ulong } -> c_long
    ~ [Desc] for [x86_64: 320, aarch64: 294, riscv64: 294],
  kexec_load(entry: c_ulong, nr_segments: c_ulong, segments: *mut kexec_segment, flags: c_ulong) /
    { entry: c_ulong, nr_segments: c_ulong, segments: Vec<kexec_segment>, flags: c_ulong } -> c_long
    ~ [] for [x86_64: 246, aarch64: 104, riscv64: 104],
  keyctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) /
    { option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong } -> c_long ~ [] for [x86_64: 250, aarch64: 219, riscv64: 219],
  kill(pid: pid_t, sig: c_int) / { pid: pid_t, sig: c_int } -> c_int ~ [Signal, Process] for [x86_64: 62, aarch64: 129, riscv64: 129],
  // TODO: rule_type and rule_attr forms a sum type.
  landlock_add_rule(ruleset_fd: RawFd, rule_type: c_long, rule_attr: *const c_void, flags: u32) /
    { ruleset_fd: RawFd, rule_type: c_long, rule_attr: Vec<u8>, flags: u32 } -> c_int ~ [Desc] for [x86_64: 445, aarch64: 445, riscv64: 445],
  landlock_create_ruleset(ruleset_attr: *const landlock_ruleset_attr, size: size_t, flags: u32) /
    { ruleset_attr: landlock_ruleset_attr, size: size_t, flags: u32 } -> c_int ~ [Desc] for [x86_64: 444, aarch64: 444, riscv64: 444],
  landlock_restrict_self(ruleset_fd: RawFd, flags: u32) / { ruleset_fd: RawFd, flags: u32 } -> c_int ~ [Desc] for [x86_64: 446, aarch64: 446, riscv64: 446],
  lchown(pathname: *const c_char, owner: uid_t, group: gid_t) / { pathname: PathBuf, owner: uid_t, group: gid_t } -> c_int ~ [File] for [x86_64: 94],
  // lchown32
  lgetxattr(pathname: *const c_char, name: *const c_char, value: *mut c_void, size: size_t) /
  { pathname: PathBuf, name: CString, size: size_t } -> ssize_t + { value: Vec<u8> } ~ [File] for [x86_64: 192, aarch64: 9, riscv64: 9],
  link(oldpath: *const c_char, newpath: *const c_char) / { oldpath: PathBuf, newpath: PathBuf } -> c_int ~ [File] for [x86_64: 86],
  linkat(olddirfd: RawFd, oldpath: *const c_char, newdirfd: RawFd, newpath: *const c_char, flags: c_int) /
    { olddirfd: RawFd, oldpath: PathBuf, newdirfd: RawFd, newpath: PathBuf, flags: c_int } -> c_int
    ~ [Desc, File] for [x86_64: 265, aarch64: 37, riscv64: 37],
  listen(sockfd: RawFd, backlog: c_int) / { sockfd: RawFd, backlog: c_int } -> c_int ~ [Network] for [x86_64: 50, aarch64: 201, riscv64: 201],
  // listmount: https://lwn.net/Articles/950569/
  listmount(req: *const __mount_arg, buf: *mut u64, bufsize: size_t, flags: c_uint) /
    { req: __mount_arg, bufsize: size_t, flags: c_uint } -> c_int + { buf: Vec<u64> } ~ [] for [x86_64: 458, aarch64: 458, riscv64: 458],
  listxattr(path: *const c_char, list: *mut c_char, size: size_t) /
    { path: PathBuf, size: size_t } -> ssize_t + { list: Option<Vec<CString>> } ~ [File] for [x86_64: 194, aarch64: 11, riscv64: 11],
  llistxattr(path: *const c_char, list: *mut c_char, size: size_t) /
    { path: PathBuf, size: size_t } -> ssize_t + { list: Option<Vec<CString>> } ~ [File] for [x86_64: 195, aarch64: 12, riscv64: 12],
  lookup_dcookie(cookie: u64, buffer: *mut c_char, len: size_t) /
    { cookie: u64, len: size_t } -> c_long + { buffer: PathBuf } ~ [] for [x86_64: 212, aarch64: 18, riscv64: 18],
  lremovexattr(path: *const c_char, name: *const c_char) / { path: PathBuf, name: CString } -> c_int ~ [File] for [x86_64: 198, aarch64: 15, riscv64: 15],
  lseek(fd: RawFd, offset: off_t, whence: c_int) / { fd: RawFd, offset: off_t, whence: c_int } -> off_t ~ [Desc] for [x86_64: 8, aarch64: 62, riscv64: 62],
  lsetxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: size_t, flags: c_int) /
    { path: PathBuf, name: CString, value: CString, size: size_t, flags: c_int } -> c_int ~ [File] for [x86_64: 189, aarch64: 6, riscv64: 6],
  // lsm: https://lwn.net/Articles/919545/
  // TODO: how to deal with DST arrays?
  lsm_get_self_attr(attr: c_uint, ctx: *mut c_void, size: *mut u32, flags: u32) / { attr: c_uint, size: Result<u32, InspectError>, flags: u32 }
    -> c_int + { ctx: Vec<u8> } ~ [] for [x86_64: 459, aarch64: 459, riscv64: 459],
  lsm_list_modules(ids: *mut u64, size: *mut u32, flags: u32) / { size: Result<u32, InspectError>, flags: u32 }
    -> c_int + { ids: Vec<u64> } ~ [] for [x86_64: 461, aarch64: 461, riscv64: 461],
  lsm_set_self_attr(attr: c_uint, ctx: *const c_void, size: u32, flags: u32) /
    { attr: c_uint, ctx: Vec<u8>, size: u32, flags: u32 } -> c_int ~ [] for [x86_64: 460, aarch64: 460, riscv64: 460],
  lstat(pathname: *const c_char, statbuf: *mut stat) / { pathname: PathBuf } -> c_int + { statbuf: stat } ~ [File, LStat, StatLike] for [x86_64: 6],
  // lstat64
  madvise(addr: *mut c_void, length: size_t, advice: c_int) / { addr: AddressType, length: size_t, advice: c_int } -> c_int
    ~ [Memory] for [x86_64: 28, aarch64: 233, riscv64: 233],
  map_shadow_stack(addr: *mut c_void, len: c_ulong, flags: c_int) / { addr: AddressType, len: c_ulong, flags: c_int } -> c_int
    ~ [Memory] for [x86_64: 453, aarch64: 453, riscv64: 453],
  mbind(addr: *mut c_void, len: c_ulong, mode: c_int, nodemask: *const c_ulong, maxnode: c_ulong, flags: c_uint) /
    { len: c_ulong, mode: c_int, nodemask: Vec<c_ulong>, maxnode: c_ulong, flags: c_uint } -> c_long
    ~ [Memory] for [x86_64: 237, aarch64: 235, riscv64: 235],
  membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) / { cmd: c_int, flags: c_int, cpu_id: c_int } -> c_int
    ~ [Memory] for [x86_64: 375, aarch64: 375, riscv64: 375],
  memfd_create(name: *const c_char, flags: c_uint) / { name: CString, flags: c_uint } -> RawFd
    ~ [Desc] for [x86_64: 319, aarch64: 279, riscv64: 279],
  memfd_secret(flags: c_uint) / { flags: c_uint } -> RawFd ~ [Desc] for [x86_64: 384, aarch64: 384, riscv64: 384],
  // memory_ordering
  // migrate_pages: TODO: what's the size of the Vec
  migrate_pages(pid: pid_t, maxnode: c_ulong, old_nodes: *const c_ulong, new_nodes: *const c_ulong) /
    { pid: pid_t, maxnode: c_ulong, old_nodes: Vec<c_ulong>, new_nodes: Vec<c_ulong> } -> c_long
    ~ [Memory] for [x86_64: 256, aarch64: 238, riscv64: 238],
  // mincore: vec is at least of len (length+PAGE_SIZE-1) / PAGE_SIZE, where PAGE_SIZE is sysconf(_SC_PAGESIZE)
  mincore(addr: *mut c_void, length: size_t, vec: *mut c_uchar) / { addr: AddressType, length: size_t } -> c_int + { vec: Vec<c_uchar> }
    ~ [Memory] for [x86_64: 27, aarch64: 232, riscv64: 232],
  mkdir(pathname: *const c_char, mode: mode_t) / { pathname: PathBuf, mode: mode_t } -> c_int ~ [File] for [x86_64: 83],
  mkdirat(dirfd: RawFd, pathname: *const c_char, mode: mode_t) / { dirfd: RawFd, pathname: PathBuf, mode: mode_t } -> c_int
    ~ [Desc, File] for [x86_64: 258, aarch64: 34, riscv64: 34],
  mknod(pathname: *const c_char, mode: mode_t, dev: dev_t) / { pathname: PathBuf, mode: mode_t, dev: dev_t } -> c_int ~ [File] for [x86_64: 133],
  mknodat(dirfd: RawFd, pathname: *const c_char, mode: mode_t, dev: dev_t) /
    { dirfd: RawFd, pathname: PathBuf, mode: mode_t, dev: dev_t } -> c_int ~ [Desc, File] for [x86_64: 259, aarch64: 33, riscv64: 33],
  mlock(addr: *const c_void, len: size_t) / { addr: AddressType, len: size_t } -> c_int ~ [Memory] for [x86_64: 149, aarch64: 228, riscv64: 228],
  mlock2(start: *const c_void, len: size_t, flags: c_int) / { start: AddressType, len: size_t, flags: c_int } -> c_int
    ~ [Memory] for [x86_64: 325, aarch64: 284, riscv64: 284],
  mlockall(flags: c_int) / { flags: c_int } -> c_int ~ [Memory] for [x86_64: 151, aarch64: 230, riscv64: 230],
  mmap(addr: *mut c_void, length: size_t, prot: c_int, flags: c_int, fd: RawFd, offset: off_t) /
    { addr: AddressType, length: size_t, prot: c_int, flags: c_int, fd: RawFd, offset: off_t } -> AddressType
    ~ [Memory] for [x86_64: 9, aarch64: 222, riscv64: 222],
  // mmap2
  modify_ldt(func: c_int, ptr: *mut c_void, bytecount: c_ulong) / { func: c_int, ptr: AddressType, bytecount: c_ulong } -> c_int
    ~ [] for [x86_64: 154],
  mount(source: *const c_char, target: *const c_char, filesystemtype: *const c_char, mountflags: c_ulong, data: *const c_void) /
    { source: CString, target: PathBuf, filesystemtype: CString, mountflags: c_ulong, data: Option<CString> } -> c_int
    ~ [File] for [x86_64: 40, aarch64: 165, riscv64: 165],
  // mount_setattr: TODO: the mount_attr struct is extensible
  mount_setattr(dirfd: RawFd, pathname: *const c_char, flags: c_uint, attr: *mut mount_attr, size: size_t) /
    { dirfd: RawFd, pathname: PathBuf, flags: c_uint, attr: Vec<mount_attr>, size: size_t } -> c_int
    ~ [Desc, File] for [x86_64: 442, aarch64: 442, riscv64: 442],
  move_mount(from_dfd: RawFd, from_path: *const c_char, to_dfd: RawFd, to_path: *const c_char, ms_flags: c_uint) /
    { from_dfd: RawFd, from_path: PathBuf, to_dfd: RawFd, to_path: PathBuf, ms_flags: c_uint } -> c_int
    ~ [Desc, File] for [x86_64: 429, aarch64: 429, riscv64: 429],
  // move_pages: pages, nodes and status are arrays of size count
  move_pages(pid: pid_t, count: c_ulong, pages: *mut *mut c_void, nodes: *const c_int, status: *mut c_int, flags: c_int) /
    { pid: pid_t, count: c_ulong, pages: Vec<AddressType>, nodes: Vec<c_int>, flags: c_int } -> c_long + { status: Vec<c_int> }
    ~ [Memory] for [x86_64: 279, aarch64: 239, riscv64: 239],
  mprotect(addr: *mut c_void, len: size_t, prot: c_int) / { addr: AddressType, len: size_t, prot: c_int } -> c_int
    ~ [Memory] for [x86_64: 10, aarch64: 226, riscv64: 226],
  mq_getsetattr(mqdes: mqd_t, newattr: *const mq_attr, oldattr: *mut mq_attr) /
    { mqdes: mqd_t, newattr: mq_attr, oldattr: mq_attr } -> c_int + { oldattr: mq_attr }
    ~ [Desc] for [x86_64: 245, aarch64: 185, riscv64: 185],
  mq_notify(mqdes: mqd_t, sevp: *const sigevent) / { mqdes: mqd_t, sevp: sigevent } -> c_int ~ [Desc] for [x86_64: 244, aarch64: 184, riscv64: 184],
  mq_open(name: *const c_char, oflag: c_int, mode: mode_t, attr: *mut mq_attr) /
    { name: CString, oflag: c_int, mode: mode_t, attr: Option<mq_attr> } -> mqd_t
    ~ [Desc] for [x86_64: 240, aarch64: 180, riscv64: 180],
  mq_timedreceive(mqdes: mqd_t, msg_ptr: *mut *mut c_char, msg_len: size_t, msg_prio: *mut c_uint, abs_timeout: *const timespec) /
    { mqdes: mqd_t, msg_len: size_t, abs_timeout: timespec } -> ssize_t + { msg_ptr: Vec<CString>, msg_prio: Option<Vec<c_uint>> }
    ~ [Desc] for [x86_64: 243, aarch64: 183, riscv64: 183],
  // mq_timedreceive_time64
  mq_timedsend(mqdes: mqd_t, msg_ptr: *const c_char, msg_len: size_t, msg_prio: c_uint, abs_timeout: *const timespec) /
    { mqdes: mqd_t, msg_ptr: CString, msg_len: size_t, msg_prio: c_uint, abs_timeout: timespec } -> c_int
    ~ [Desc] for [x86_64: 242, aarch64: 182, riscv64: 182],
  // mq_timedsend_time64
  mq_unlink(name: *const c_char) / { name: CString } -> c_int ~ [] for [x86_64: 241, aarch64: 181, riscv64: 181],
  mremap(old_address: *mut c_void, old_size: size_t, new_size: size_t, flags: c_int, new_address: *mut c_void) /
    { old_address: AddressType, old_size: size_t, new_size: size_t, flags: c_int, new_address: AddressType } -> AddressType
    ~ [Memory] for [x86_64: 25, aarch64: 216, riscv64: 216],
  // mseal: 6.10 https://lwn.net/Articles/954936/
  mseal(start: AddressType, len: size_t, types: c_ulong, flags: c_ulong) / { start: AddressType, len: size_t, types: c_ulong, flags: c_ulong } -> c_int
    ~ [Memory] for [x86_64: 462, aarch64: 462, riscv64: 462],
  msgctl(msqid: c_int, cmd: c_int, buf: *mut msqid_ds) / { msqid: c_int, cmd: c_int } -> c_int + { buf: msqid_ds }
    ~ [] for [x86_64: 71, aarch64: 187, riscv64: 187],
  msgget(key: key_t, msgflg: c_int) / { key: key_t, msgflg: c_int } -> c_int ~ [] for [x86_64: 68, aarch64: 186, riscv64: 186],
  // TODO: msgp is a ptr to DST msgbuf { long mtype; char mtext[msgsz]; }
  msgrcv(msqid: c_int, msgp: *mut c_void, msgsz: size_t, msgtyp: c_long, msgflg: c_int) /
    { msqid: c_int, msgsz: size_t, msgtyp: c_long, msgflg: c_int } -> ssize_t + { msgp: Vec<u8> }
    ~ [] for [x86_64: 70, aarch64: 188, riscv64: 188],
  msgsnd(msqid: c_int, msgp: *const c_void, msgsz: size_t, msgflg: c_int) /
    { msqid: c_int, msgp: Vec<u8>, msgsz: size_t, msgflg: c_int } -> c_int ~ [] for [x86_64: 69, aarch64: 189, riscv64: 189],
  msync(addr: *mut c_void, length: size_t, flags: c_int) / { addr: AddressType, length: size_t, flags: c_int } -> c_int
    ~ [Memory] for [x86_64: 26, aarch64: 227, riscv64: 227],
  // multiplexer
  munlock(addr: *const c_void, len: size_t) / { addr: AddressType, len: size_t } -> c_int ~ [Memory] for [x86_64: 150, aarch64: 229, riscv64: 229],
  munlockall() / {} -> c_int ~ [Memory] for [x86_64: 152, aarch64: 231, riscv64: 231],
  munmap(addr: *mut c_void, length: size_t) / { addr: AddressType, length: size_t } -> c_int ~ [Memory] for [x86_64: 11, aarch64: 215, riscv64: 215],
  // TODO: DST file_handle
  name_to_handle_at(dirfd: RawFd, pathname: *const c_char, handle: *mut c_void, mount_id: *mut c_int, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, flags: c_int } -> c_int + { handle: Vec<u8>, mount_id: c_int }
    ~ [Desc, File] for [x86_64: 303, aarch64: 264, riscv64: 264],
  nanosleep(req: *const timespec, rem: *mut timespec) / { req: timespec } -> c_int + { rem: Option<timespec> }
    ~ [Clock] for [x86_64: 35, aarch64: 230, riscv64: 230],
  newfstatat(dirfd: RawFd, pathname: *const c_char, statbuf: *mut stat, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, flags: c_int } -> c_int + { statbuf: stat }
    ~ [Desc, File, FStat, StatLike] for [x86_64: 262, aarch64: 79, riscv64: 79],
  // nice
  // old_adjtimex
  // oldfstat
  // oldlstat
  // oldolduname
  // oldstat
  // oldumount
  // olduname
  open(pathname: *const c_char, flags: c_int, mode: mode_t) / { pathname: PathBuf, flags: c_int, mode: mode_t } -> RawFd
    ~ [Desc, File] for [x86_64: 2, aarch64: 56, riscv64: 56],
  open_by_handle_at(mount_fd: RawFd, handle: *mut c_void, flags: c_int) /
    { mount_fd: RawFd, handle: Vec<u8>, flags: c_int } -> RawFd ~ [Desc] for [x86_64: 304, aarch64: 265, riscv64: 265],
  open_tree(dirfd: RawFd, path: *const c_char, flags: c_uint) / { dirfd: RawFd, path: PathBuf, flags: c_uint } -> c_int
    ~ [Desc, File] for [x86_64: 428, aarch64: 428, riscv64: 428],
  openat(dirfd: RawFd, pathname: *const c_char, flags: c_int, mode: mode_t) /
    { dirfd: RawFd, pathname: PathBuf, flags: c_int, mode: mode_t } -> RawFd ~ [Desc, File] for [x86_64: 257, aarch64: 56, riscv64: 56],
  openat2(dirfd: RawFd, pathname: *const c_char, how: *mut open_how, size: size_t) /
    { dirfd: RawFd, pathname: PathBuf, how: open_how, size: size_t } -> c_int ~ [Desc, File] for [x86_64: 437, aarch64: 437, riscv64: 437],
  // or1k_atomic
  // osf_*
  pause() / {} -> c_int ~ [Signal] for [x86_64: 29, aarch64: 34, riscv64: 34],
  // pciconfig_iobase
  // pciconfig_read
  // pciconfig_write
  // perf_event_open: TODO: attr is perf_event_attr struct
  perf_event_open(attr: *mut c_void, pid: pid_t, cpu: c_int, group_fd: RawFd, flags: c_ulong) /
    { attr: AddressType, pid: pid_t, cpu: c_int, group_fd: RawFd, flags: c_ulong } -> RawFd
    ~ [Desc] for [x86_64: 298, aarch64: 241, riscv64: 241],
  // perfctr
  personality(persona: c_ulong) / { persona: c_ulong } -> c_int ~ [] for [x86_64: 135, aarch64: 92, riscv64: 92],
  pidfd_getfd(pidfd: RawFd, targetfd: RawFd, flags: c_uint) / { pidfd: RawFd, targetfd: RawFd, flags: c_uint } -> RawFd
    ~ [Desc] for [x86_64: 438, aarch64: 438, riscv64: 438],
  pidfd_open(pid: pid_t, flags: c_uint) / { pid: pid_t, flags: c_uint } -> RawFd ~ [Desc] for [x86_64: 434, aarch64: 434, riscv64: 434],
  pidfd_send_signal(pidfd: RawFd, sig: c_int, info: *mut siginfo_t, flags: c_uint) /
    { pidfd: RawFd, sig: c_int, info: Option<siginfo_t>, flags: c_uint } -> c_int
    ~ [Desc, Signal, Process] for [x86_64: 424, aarch64: 424, riscv64: 424],
  pipe(pipefd: *mut c_int) / {} -> c_int + { pipefd: [RawFd; 2] } ~ [Desc] for [x86_64: 22],
  pipe2(pipefd: *mut c_int, flags: c_int) / { flags: c_int } -> c_int + { pipefd: [RawFd; 2] } ~ [Desc] for [x86_64: 293, aarch64: 59, riscv64: 59],
  pivot_root(new_root: *const c_char, put_old: *const c_char) / { new_root: PathBuf, put_old: PathBuf } -> c_int
    ~ [File] for [x86_64: 155, aarch64: 41, riscv64: 41],
  pkey_alloc(flags: c_uint, access_rights: c_uint) / { flags: c_uint, access_rights: c_uint } -> c_int ~ [] for [x86_64: 330, aarch64: 289, riscv64: 289],
  pkey_free(pkey: c_int) / { pkey: c_int } -> c_int ~ [] for [x86_64: 331, aarch64: 290, riscv64: 290],
  pkey_mprotect(addr: *mut c_void, len: size_t, prot: c_int, pkey: c_int) /
    { addr: AddressType, len: size_t, prot: c_int, pkey: c_int } -> c_int ~ [Memory] for [x86_64: 329, aarch64: 288, riscv64: 288],
  poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) / { nfds: nfds_t, timeout: c_int } -> c_int + { fds: Vec<pollfd> }
    ~ [Desc] for [x86_64: 7],
  ppoll(fds: *mut pollfd, nfds: nfds_t, tmo_p: *const timespec, sigmask: *const sigset_t) /
    { nfds: nfds_t, tmo_p: Option<timespec>, sigmask: Option<sigset_t> } -> c_int + { fds: Vec<pollfd> }
    ~ [Desc] for [x86_64: 271, aarch64: 73, riscv64: 73],
  // ppoll_time64
  prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) /
    { option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong } -> c_int
    ~ [Clock] for [x86_64: 157, aarch64: 167, riscv64: 167],
  pread64(fd: RawFd, buf: *mut c_void, count: size_t, offset: loff_t) /
    { fd: RawFd, count: size_t, offset: loff_t } -> ssize_t + { buf: Vec<u8> }
    ~ [Desc] for [x86_64: 67, aarch64: 17, riscv64: 17],
  preadv(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t) /
    { fd: RawFd, iov: Vec<iovec>, offset: off_t } -> ssize_t ~ [Desc] for [x86_64: 295, aarch64: 69, riscv64: 69],
  preadv2(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t, flags: c_int) /
    { fd: RawFd, iov: Vec<iovec>, offset: off_t, flags: c_int } -> ssize_t ~ [Desc] for [x86_64: 327, aarch64: 286, riscv64: 286],
  prlimit64(pid: pid_t, resource: c_int, new_limit: *const rlimit64, old_limit: *mut rlimit64) /
    { pid: pid_t, resource: c_int, new_limit: Option<rlimit64>, old_limit: Option<rlimit64> } -> c_int + { old_limit: Option<rlimit64> }
    ~ [] for [x86_64: 302, aarch64: 261, riscv64: 261],
  process_madvise(pidfd: RawFd, iovec: *const iovec, vlen: size_t, advice: c_int, flags: c_uint) /
    { pidfd: RawFd, iovec: Vec<iovec>, vlen: size_t, advice: c_int, flags: c_uint } -> c_int
    ~ [Desc] for [x86_64: 440, aarch64: 440, riscv64: 440],
  process_mrelease(pidfd: RawFd, flags: c_uint) / { pidfd: RawFd, flags: c_uint } -> c_int ~ [Desc] for [x86_64: 448, aarch64: 448, riscv64: 448],
  process_vm_readv(pid: pid_t, local_iov: *const iovec, liovcnt: c_ulong, remote_iov: *const iovec, riovcnt: c_ulong, flags: c_ulong) /
    { pid: pid_t, local_iov: Vec<iovec>, remote_iov: Vec<iovec>, flags: c_ulong } -> ssize_t
    ~ [] for [x86_64: 310, aarch64: 270, riscv64: 270],
  process_vm_writev(pid: pid_t, local_iov: *const iovec, liovcnt: c_ulong, remote_iov: *const iovec, riovcnt: c_ulong, flags: c_ulong) /
    { pid: pid_t, local_iov: Vec<iovec>, remote_iov: Vec<iovec>, flags: c_ulong } -> ssize_t
    ~ [] for [x86_64: 311, aarch64: 271, riscv64: 271],
  // TODO: sigmask is { const kernel_sigset_t *ss;  size_t ss_len; /* Size (in bytes) of object pointed to by 'ss' */ }
  pselect6(nfds: c_int, readfds: *mut fd_set, writefds: *mut fd_set, exceptfds: *mut fd_set, timeout: *mut timespec, sigmask: *const c_void) /
    { readfds: Option<fd_set>, writefds: Option<fd_set>, exceptfds: Option<fd_set>, timeout: Option<timespec>, sigmask: Option<sigset_t> }
    -> c_int + { readfds: Option<fd_set>, writefds: Option<fd_set>, exceptfds: Option<fd_set> }
    ~ [Desc] for [x86_64: 270, aarch64: 72, riscv64: 72],
  // pselect6_time64
  ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) / { } -> c_long
    ~ [] for [x86_64: 101, aarch64: 117, riscv64: 117],
  pwrite64(fd: RawFd, buf: *const c_void, count: size_t, offset: loff_t) /
    { fd: RawFd, buf: Vec<u8>, count: size_t, offset: loff_t } -> ssize_t ~ [Desc] for [x86_64: 18, aarch64: 68, riscv64: 68],
  pwritev(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t) /
    { fd: RawFd, iov: Vec<iovec>, offset: off_t } -> ssize_t ~ [Desc] for [x86_64: 296, aarch64: 70, riscv64: 70],
  pwritev2(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t, flags: c_int) /
    { fd: RawFd, iov: Vec<iovec> @ counted_by(iovcnt), offset: off_t, flags: c_int } -> ssize_t ~ [Desc] for [x86_64: 328, aarch64: 287, riscv64: 287],
}

// pub use cfg_if_has_syscall;
