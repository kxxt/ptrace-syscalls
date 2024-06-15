#![allow(non_upper_case_globals)]

use std::path::PathBuf;
use std::{
  ffi::{c_int, CString},
  os::fd::RawFd,
};

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, syscall_res_from_regs, PtraceRegisters},
  types::*,
  InspectError, InspectResult, SyscallNumber, SyscallStopInspect,
};
use crate::{ptrace_getregs, SyscallGroups, SyscallGroupsGetter};
use enumflags2::BitFlags;
use nix::errno::Errno;
use nix::libc::{
  c_char, c_long, c_uchar, c_uint, c_ulong, c_void, clock_t, clockid_t, clone_args, dev_t,
  epoll_event, fd_set, gid_t, id_t, idtype_t, iocb, iovec, itimerspec, itimerval, key_t, loff_t,
  mmsghdr, mode_t, mq_attr, mqd_t, msghdr, msqid_ds, nfds_t, off_t, open_how, pid_t, pollfd,
  rlimit, rlimit64, rusage, sched_attr, sched_param, sembuf, shmid_ds, sigaction, sigevent,
  siginfo_t, sigset_t, size_t, sockaddr, socklen_t, ssize_t, stack_t, stat, statfs, statx, sysinfo,
  time_t, timer_t, timespec, timeval, timex, tms, uid_t, utimbuf, utsname,
};
use nix::sys::ptrace::AddressType;
use nix::unistd::Pid;
use std::sync::Arc;
use tracer_syscalls_macros::gen_syscalls;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnknownArgs {
  pub number: isize,
  pub args: [usize; 6],
}

impl UnknownArgs {
  fn from_regs(regs: &PtraceRegisters) -> Self {
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

impl SyscallNumber for UnknownArgs {
  fn syscall_number(&self) -> isize {
    self.number
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
    { socketfd: RawFd, addr: sockaddr, addrlen: InspectResult<socklen_t> } -> c_int + { addr: sockaddr, addrlen: InspectResult<socklen_t> }
    ~ [Network] for [x86_64: 43, aarch64: 202, riscv64: 202],
  accept4(socketfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t, flags: c_int) /
    { socketfd: RawFd, addr: sockaddr, addrlen: InspectResult<socklen_t>, flags: c_int } -> c_int + { addr: sockaddr, addrlen: InspectResult<socklen_t> }
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
  // cachestat: TODO: https://github.com/golang/go/issues/61917
  cachestat(fd: RawFd, cstat_range: *mut cachestat_range, cstat: *mut cachestat, flags: c_uint) /
    { fd: RawFd, cstat_range: cachestat_range, cstat: cachestat, flags: c_uint } -> c_int
    ~ [Desc] for [x86_64: 451, aarch64: 451, riscv64: 451],
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
   { parent_tid: InspectResult<pid_t>, child_tid: InspectResult<pid_t> } ~ [Process] for [x86_64: 56],
  clone(flags: c_ulong, stack: AddressType, parent_tid: *mut pid_t, tls: c_ulong, child_tid: *mut pid_t) /
   { flags: c_ulong, stack: AddressType, tls: c_ulong } -> c_long +
   { parent_tid: InspectResult<pid_t>, child_tid: InspectResult<pid_t> } ~ [Process] for [aarch64: 220, riscv64: 220],
  clone3(cl_args: *mut clone_args, size: size_t) / { cl_args: clone_args, size: size_t } -> c_int ~ [Process] for [x86_64: 435, aarch64: 435, riscv64: 435],
  close(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 3, aarch64: 57, riscv64: 57],
  close_range(first: c_uint, last: c_uint, flags: c_uint) / { first: c_uint, last: c_uint, flags: c_uint }
    -> c_int ~ [] for [x86_64: 436, aarch64: 436, riscv64: 436],
  connect(sockfd: RawFd, addr: *const sockaddr, addrlen: socklen_t) /
    { sockfd: RawFd, addr: sockaddr, addrlen: socklen_t } -> c_int ~ [Network] for [x86_64: 42, aarch64: 203, riscv64: 203],
  copy_file_range(fd_in: RawFd, off_in: *mut off_t, fd_out: RawFd, off_out: *mut off_t, len: size_t, flags: c_uint) /
    { fd_in: RawFd, off_in: InspectResult<off_t>, fd_out: RawFd, off_out: InspectResult<off_t>, len: size_t, flags: c_uint }
    -> ssize_t + { off_in: InspectResult<off_t>, off_out: InspectResult<off_t> } ~ [Desc] for [x86_64: 326, aarch64: 285, riscv64: 285],
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
  fremovexattr(fd: RawFd, name: *const c_char) / { fd: RawFd, name: CString } -> c_int ~ [Desc] for [x86_64: 199, aarch64: 16, riscv64: 16],
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
    { uaddr: InspectResult<u32>, futex_op: c_int, val: u32, val2: usize, uaddr2: InspectResult<u32>, val3: u32 }
    -> c_long + { uaddr: InspectResult<u32>, uaddr2: InspectResult<u32> } ~ [] for [x86_64: 202, aarch64: 98, riscv64: 98],
  // https://elixir.bootlin.com/linux/v6.9.3/source/include/linux/syscalls.h#L568
  // futex_requeue: waiters is always a two-element array of futex_waitv. TODO: design a better rust interface
  futex_requeue(waiters: *mut futex_waitv, flags: c_uint, nr_wake: c_int, nr_requeue: c_int) /
    { waiters: Vec<futex_waitv>, flags: c_uint, nr_wake: c_int, nr_requeue: c_int }
    -> c_long + { waiters: Vec<futex_waitv> } ~ [] for [x86_64: 456, aarch64: 456, riscv64: 456],
  // futex_time64
  futex_wait(uaddr: *mut u32, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: *mut timespec, clockid: clockid_t) /
    { uaddr: InspectResult<u32>, val: c_ulong, mask: c_ulong, flags: c_uint, timespec: timespec, clockid: clockid_t }
    -> c_long + { uaddr: InspectResult<u32> } ~ [] for [x86_64: 455, aarch64: 455, riscv64: 455],
  futex_waitv(waiters: *mut futex_waitv, nr_futexes: c_uint, flags: c_uint, timeout: *mut timespec, clockid: clockid_t) /
    { waiters: Vec<futex_waitv>, nr_futexes: c_uint, flags: c_uint, timeout: timespec, clockid: clockid_t }
    -> c_long + { waiters: Vec<futex_waitv> } ~ [] for [x86_64: 449, aarch64: 449, riscv64: 449],
  futex_wake(uaddr: *mut u32, mask: c_ulong, nr: c_int, flags: c_uint) /
    { uaddr: InspectResult<u32>, mask: c_ulong, nr: c_int, flags: c_uint }
    -> c_long + { uaddr: InspectResult<u32> } ~ [] for [x86_64: 454, aarch64: 454, riscv64: 454],
  futimesat(dirfd: RawFd, pathname: *const c_char, times: *const timeval) /
    { dirfd: RawFd, pathname: PathBuf, times: [timeval;2] } -> c_int ~ [Desc, File] for [x86_64: 261],
  // get_mempolicy: nodemask: [c_ulong; (maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH]
  get_mempolicy(mode: *mut c_int, nodemask: *mut c_ulong, maxnode: c_ulong, addr: AddressType, flags: c_ulong) /
    { maxnode: c_ulong, addr: AddressType, flags: c_ulong } -> c_long +
    { mode: InspectResult<Option<c_int>>, nodemask: Option<Vec<c_ulong>> } ~ [Memory] for [x86_64: 239, aarch64: 236, riscv64: 236],
  get_robust_list(pid: pid_t, head_ptr: *mut *mut robust_list_head, len_ptr: *mut size_t) /
    { pid: pid_t, head_ptr: InspectResult<AddressType>, len_ptr: size_t } -> c_long ~ [] for [x86_64: 274, aarch64: 100, riscv64: 100],
  get_thread_area(u_info: *mut user_desc) / { u_info: user_desc } -> c_int + { u_info: user_desc } ~ [] for [x86_64: 211],
  getcpu(cpu: *mut c_uint, node: *mut c_uint) /
    { cpu: InspectResult<Option<c_uint>>, node: InspectResult<Option<c_uint>> } -> c_int ~ [] for [x86_64: 309, aarch64: 168, riscv64: 168],
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
    { sockfd: RawFd, addr: sockaddr, addrlen: InspectResult<socklen_t> } -> c_int + { addr: sockaddr, addrlen: InspectResult<socklen_t> }
    ~ [Network] for [x86_64: 52, aarch64: 205, riscv64: 205],
  getpgid(pid: pid_t) / { pid: pid_t } -> pid_t ~ [] for [x86_64: 121, aarch64: 155, riscv64: 155],
  getpgrp() / {} -> pid_t ~ [Pure] for [x86_64: 111],
  getpid() / {} -> pid_t ~ [Pure] for [x86_64: 39, aarch64: 172, riscv64: 172],
  getppid() / {} -> pid_t ~ [Pure] for [x86_64: 110, aarch64: 173, riscv64: 173],
  getpriority(which: c_int, who: id_t) / { which: c_int, who: id_t } -> c_int ~ [] for [x86_64: 140, aarch64: 141, riscv64: 141],
  getrandom(buf: *mut c_void, buflen: size_t, flags: c_uint) / { buflen: size_t, flags: c_uint } -> ssize_t + { buf: Vec<u8> }
    ~ [] for [x86_64: 318, aarch64: 278, riscv64: 278],
  getresgid(rgid: *mut gid_t, egid: *mut gid_t, sgid: *mut gid_t) / {}
    -> c_int + { rgid: InspectResult<gid_t>, egid: InspectResult<gid_t>, sgid: InspectResult<gid_t> }
    ~ [Creds] for [x86_64: 120, aarch64: 150, riscv64: 150],
  // getresgid32
  getresuid(ruid: *mut uid_t, euid: *mut uid_t, suid: *mut uid_t) / {}
    -> c_int + { ruid: InspectResult<uid_t>, euid: InspectResult<uid_t>, suid: InspectResult<uid_t> }
    ~ [Creds] for [x86_64: 118, aarch64: 148, riscv64: 148],
  // getresuid32
  getrlimit(resource: c_int, rlim: *mut rlimit) / { resource: c_int } -> c_int + { rlim: rlimit } ~ [] for [x86_64: 97, aarch64: 163, riscv64: 163],
  getrusage(who: c_int, usage: *mut rusage) / { who: c_int } -> c_int + { usage: rusage } ~ [] for [x86_64: 98, aarch64: 165, riscv64: 165],
  getsid(pid: pid_t) / { pid: pid_t } -> pid_t ~ [] for [x86_64: 124, aarch64: 156, riscv64: 156],
  getsockname(sockfd: RawFd, addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { sockfd: RawFd, addrlen: InspectResult<socklen_t> } -> c_int + { addr: sockaddr, addrlen: InspectResult<socklen_t> }
    ~ [Network] for [x86_64: 51, aarch64: 204, riscv64: 204],
  getsockopt(sockfd: RawFd, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut socklen_t) /
    { sockfd: RawFd, level: c_int, optname: c_int, optlen: InspectResult<socklen_t> }
    -> c_int + { optval: Vec<u8>, optlen: InspectResult<socklen_t> }
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
  io_destroy(ctx_id: aio_context_t) / { ctx_id: aio_context_t } -> c_int ~ [] for [x86_64: 207, aarch64: 1, riscv64: 1],

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
  lsm_get_self_attr(attr: c_uint, ctx: *mut c_void, size: *mut u32, flags: u32) / { attr: c_uint, size: InspectResult<u32>, flags: u32 }
    -> c_int + { ctx: Vec<u8> } ~ [] for [x86_64: 459, aarch64: 459, riscv64: 459],
  lsm_list_modules(ids: *mut u64, size: *mut u32, flags: u32) / { size: InspectResult<u32>, flags: u32 }
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
    ~ [Memory] for [x86_64: 324, aarch64: 283, riscv64: 283],
  memfd_create(name: *const c_char, flags: c_uint) / { name: CString, flags: c_uint } -> RawFd
    ~ [Desc] for [x86_64: 319, aarch64: 279, riscv64: 279],
  memfd_secret(flags: c_uint) / { flags: c_uint } -> RawFd ~ [Desc] for [x86_64: 447, aarch64: 447, riscv64: 447],
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
    ~ [File] for [x86_64: 165, aarch64: 40, riscv64: 40],
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
  pause() / {} -> c_int ~ [Signal] for [x86_64: 34],
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
    ~ [Desc] for [x86_64: 17, aarch64: 67, riscv64: 67],
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
    { fd: RawFd, buf: Vec<u8> @ counted_by(count), count: size_t, offset: loff_t } -> ssize_t ~ [Desc] for [x86_64: 18, aarch64: 68, riscv64: 68],
  pwritev(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t) /
    { fd: RawFd, iov: Vec<iovec> @ counted_by(iovcnt), offset: off_t } -> ssize_t ~ [Desc] for [x86_64: 296, aarch64: 70, riscv64: 70],
  pwritev2(fd: RawFd, iov: *const iovec, iovcnt: c_int, offset: off_t, flags: c_int) /
    { fd: RawFd, iov: Vec<iovec> @ counted_by(iovcnt), offset: off_t, flags: c_int } -> ssize_t ~ [Desc] for [x86_64: 328, aarch64: 287, riscv64: 287],
  quotactl(cmd: c_int, special: *const c_char, id: qid_t, addr: AddressType) /
    { cmd: c_int, special: Option<CString>, id: qid_t } -> c_int ~ [File] for [x86_64: 179, aarch64: 60, riscv64: 60],
  quotactl_fd(fd: RawFd, cmd: c_int, id: c_int, addr: AddressType) / { fd: RawFd, cmd: c_int, id: c_int } -> c_int
    ~ [Desc] for [x86_64: 443, aarch64: 443, riscv64: 443],
  read(fd: RawFd, buf: *mut c_void, count: size_t) / { fd: RawFd, count: size_t } -> ssize_t + { buf: Vec<u8> @ on_success_counted_by(syscall_result) }
    ~ [Desc] for [x86_64: 0, aarch64: 63, riscv64: 63],
  readahead(fd: RawFd, offset: off_t, count: size_t) / { fd: RawFd, offset: off_t, count: size_t } -> ssize_t
    ~ [Desc] for [x86_64: 187, aarch64: 213, riscv64: 213],
  // readdir(fd: RawFd, dirp: AddressType, count: c_uint) / { fd: RawFd, count: c_uint } -> c_int + { dirp: Vec<u8> } ~ [Desc] for [],
  readlink(pathname: *const c_char, buf: *mut c_char, bufsiz: size_t) / { pathname: PathBuf, bufsiz: size_t } -> ssize_t
    + { buf: Vec<u8> @ on_success_counted_by(syscall_result) } ~ [File] for [x86_64: 89],
  readlinkat(dirfd: RawFd, pathname: *const c_char, buf: *mut c_char, bufsiz: size_t) /
    { dirfd: RawFd, pathname: PathBuf, bufsiz: size_t } -> ssize_t + { buf: Vec<u8> @ on_success_counted_by(syscall_result) }
    ~ [Desc, File] for [x86_64: 267, aarch64: 78, riscv64: 78],
  readv(fd: RawFd, iov: *const iovec, iovcnt: c_int) / { fd: RawFd, iov: Vec<iovec> @ counted_by(iovcnt) } -> ssize_t
    ~ [Desc] for [x86_64: 19, aarch64: 65, riscv64: 65],
  reboot(magic: c_int, magic2: c_int, cmd: c_int, arg: *mut c_void) / { magic: c_int, magic2: c_int, cmd: c_int } -> c_int
    ~ [] for [x86_64: 169, aarch64: 142, riscv64: 142],
  //  recv
  recvfrom(sockfd: RawFd, buf: *mut c_void, len: size_t, flags: c_int, src_addr: *mut sockaddr, addrlen: *mut socklen_t) /
    { sockfd: RawFd, len: size_t, flags: c_int, src_addr: Option<sockaddr> } -> ssize_t + { buf: Vec<u8> @ on_success_counted_by(syscall_result) }
    ~ [Network] for [x86_64: 45, aarch64: 207, riscv64: 207],
  recvmmsg(sockfd: RawFd, msgvec: *mut mmsghdr, vlen: c_uint, flags: c_int, timeout: *mut timespec) /
    { sockfd: RawFd, vlen: c_uint, flags: c_int, msgvec: Vec<mmsghdr> @ counted_by(vlen), timeout: Option<timespec> } -> c_int
    ~ [Network] for [x86_64: 299, aarch64: 243, riscv64: 243],
  // recvmmsg_time64
  recvmsg(sockfd: RawFd, msg: *mut msghdr, flags: c_int) / { sockfd: RawFd, flags: c_int, msg: msghdr } -> ssize_t + { msg: msghdr }
    ~ [Network] for [x86_64: 47, aarch64: 212, riscv64: 212],
  remap_file_pages(addr: *mut c_void, size: size_t, prot: c_int, pgoff: size_t, flags: c_int) /
    { addr: AddressType, size: size_t, prot: c_int, pgoff: size_t, flags: c_int } -> c_int
    ~ [Memory] for [x86_64: 216, aarch64: 234, riscv64: 234],
  removexattr(path: *const c_char, name: *const c_char) / { path: PathBuf, name: CString } -> c_int
    ~ [File] for [x86_64: 197, aarch64: 14, riscv64: 14],
  rename(oldpath: *const c_char, newpath: *const c_char) / { oldpath: PathBuf, newpath: PathBuf } -> c_int
    ~ [File] for [x86_64: 82],
  renameat(olddirfd: RawFd, oldpath: *const c_char, newdirfd: RawFd, newpath: *const c_char) /
    { olddirfd: RawFd, oldpath: PathBuf, newdirfd: RawFd, newpath: PathBuf } -> c_int
    ~ [Desc, File] for [x86_64: 264, aarch64: 38],
  renameat2(olddirfd: RawFd, oldpath: *const c_char, newdirfd: RawFd, newpath: *const c_char, flags: c_uint) /
    { olddirfd: RawFd, oldpath: PathBuf, newdirfd: RawFd, newpath: PathBuf, flags: c_uint } -> c_int
    ~ [Desc, File] for [x86_64: 316, aarch64: 276, riscv64: 276],
  request_key(r#type: *const c_char, description: *const c_char, callout_info: *const c_char, dest_keyring: key_serial_t) /
    { r#type: CString, description: CString, callout_info: Option<CString>, dest_keyring: key_serial_t } -> key_serial_t
    ~ [] for [x86_64: 249, aarch64: 218, riscv64: 218],
  restart_syscall() / {} -> c_long ~ [] for [x86_64: 219, aarch64: 128, riscv64: 128],
  riscv_flush_icache(start: *mut c_void, end: *mut c_void, flags: c_ulong) / { start: AddressType, end: AddressType, flags: c_ulong } -> c_int
    ~ [Memory] for [riscv64: 259],
  // https://docs.kernel.org/6.5/riscv/hwprobe.html
  riscv_hwprobe(pairs: *mut riscv_hwprobe, pair_count: size_t, cpu_count: size_t, cpus: *mut c_ulong, flags: c_uint) /
    { pairs: Vec<riscv_hwprobe>, pair_count: size_t, cpu_count: size_t, cpus: Vec<c_ulong>, flags: c_uint }
    -> c_int + { pairs: Vec<riscv_hwprobe> }
    ~ [] for [riscv64: 258],
  rmdir(pathname: *const c_char) / { pathname: PathBuf } -> c_int ~ [File] for [x86_64: 84],
  rseq(rseq: *mut c_void, rseq_len: u32, flags: c_int, sig: u32) / { rseq: Arc<rseq>, rseq_len: u32, flags: c_int, sig: u32 } -> c_int
    ~ [] for [x86_64: 334, aarch64: 293, riscv64: 293],
  rt_sigaction(sig: c_int, act: *const sigaction, oact: *mut sigaction, sigsetsize: size_t) /
    { sig: c_int, act: Option<sigaction>, oact: Option<sigaction>, sigsetsize: size_t } -> c_int + { oact: Option<sigaction> }
    ~ [Signal] for [x86_64: 13, aarch64: 134, riscv64: 134],
  rt_sigpending(set: *mut sigset_t, sigsetsize: size_t) / { set: sigset_t, sigsetsize: size_t } -> c_int
    ~ [Signal] for [x86_64: 127, aarch64: 136, riscv64: 136],
  rt_sigprocmask(how: c_int, set: *const sigset_t, oldset: *mut sigset_t, sigsetsize: size_t) /
    { how: c_int, set: Option<sigset_t>, oldset: Option<sigset_t>, sigsetsize: size_t } -> c_int + { oldset: Option<sigset_t> }
    ~ [Signal] for [x86_64: 14, aarch64: 135, riscv64: 135],
  rt_sigqueueinfo(pid: pid_t, sig: c_int, info: *mut siginfo_t) / { pid: pid_t, sig: c_int, info: siginfo_t } -> c_int
    ~ [Signal, Process] for [x86_64: 129, aarch64: 138, riscv64: 138],
  // TODO: regs is pt_regs struct
  rt_sigreturn(regs: *mut c_void) / {} -> c_int ~ [Signal] for [x86_64: 15, aarch64: 139, riscv64: 139],
  rt_sigsuspend(newset: *mut sigset_t, sigsetsize: size_t) /
    { newset: sigset_t, sigsetsize: size_t } -> c_int ~ [Signal] for [x86_64: 130, aarch64: 133, riscv64: 133],
  rt_sigtimedwait(set: *const sigset_t, info: *mut siginfo_t, timeout: *const timespec, sigsetsize: size_t) /
    { set: sigset_t, info: siginfo_t, timeout: timespec, sigsetsize: size_t } -> c_int + { info: Option<siginfo_t> }
    ~ [Signal] for [x86_64: 128, aarch64: 137, riscv64: 137],
  // rt_sigtimedwait_time64
  rt_tgsigqueueinfo(tgid: pid_t, pid: pid_t, sig: c_int, info: *mut siginfo_t) /
    { tgid: pid_t, pid: pid_t, sig: c_int, info: siginfo_t } -> c_int ~ [Signal, Process] for [x86_64: 297, aarch64: 240, riscv64: 240],
  // rtas
  // sched_get_affinity
  sched_get_priority_max(policy: c_int) / { policy: c_int } -> c_int ~ [] for [x86_64: 146, aarch64: 125, riscv64: 125],
  sched_get_priority_min(policy: c_int) / { policy: c_int } -> c_int ~ [] for [x86_64: 147, aarch64: 126, riscv64: 126],
  // sched_getaffinity syscall returns (in bytes) the number of bytes placed copied into the mask buffer. arg cpusetsize is also in bytes
  sched_getaffinity(pid: pid_t, cpusetsize: size_t, mask: *mut c_ulong) /
    { pid: pid_t, cpusetsize: size_t } -> c_int + { mask: Vec<u8> }
    ~ [] for [x86_64: 204, aarch64: 123, riscv64: 123],
  sched_getattr(pid: pid_t, attr: *mut sched_attr, size: c_uint, flags: c_uint) /
    { pid: pid_t, size: c_uint, flags: c_uint } -> c_int + { attr: sched_attr }
    ~ [] for [x86_64: 315, aarch64: 275, riscv64: 275],
  sched_getparam(pid: pid_t, param: *mut sched_param) / { pid: pid_t } -> c_int + { param: sched_param }
    ~ [] for [x86_64: 143, aarch64: 121, riscv64: 121],
  sched_getscheduler(pid: pid_t) / { pid: pid_t } -> c_int ~ [] for [x86_64: 145, aarch64: 120, riscv64: 120],
  sched_rr_get_interval(pid: pid_t, tp: *mut timespec) / { pid: pid_t } -> c_int + { tp: timespec }
    ~ [] for [x86_64: 148, aarch64: 127, riscv64: 127],
  // sched_rr_get_interval_time64
  // sched_set_affinity
  sched_setaffinity(pid: pid_t, cpusetsize: size_t, mask: *const c_ulong) /
    { pid: pid_t, cpusetsize: size_t, mask: Vec<u8> } -> c_int
    ~ [] for [x86_64: 203, aarch64: 122, riscv64: 122],
  // sched_setattr size is the first field of sched_attr struct
  sched_setattr(pid: pid_t, attr: *mut sched_attr, flags: c_uint) / { pid: pid_t, attr: sched_attr, flags: c_uint } -> c_int
    ~ [] for [x86_64: 314, aarch64: 274, riscv64: 274],
  sched_setparam(pid: pid_t, param: *const sched_param) / { pid: pid_t, param: sched_param } -> c_int
    ~ [] for [x86_64: 142, aarch64: 118, riscv64: 118],
  sched_setscheduler(pid: pid_t, policy: c_int, param: *const sched_param) /
    { pid: pid_t, policy: c_int, param: sched_param } -> c_int
    ~ [] for [x86_64: 144, aarch64: 119, riscv64: 119],
  sched_yield() / {} -> c_int ~ [] for [x86_64: 24, aarch64: 124, riscv64: 124],
  // seccomp: TODO: decode args
  seccomp(operation: c_int, flags: c_uint, args: *mut c_void) / { operation: c_int, flags: c_uint } -> c_int
    ~ [] for [x86_64: 317, aarch64: 277, riscv64: 277],
  select(nfds: c_int, readfds: *mut fd_set, writefds: *mut fd_set, exceptfds: *mut fd_set, timeout: *mut timeval) /
    { nfds: c_int, readfds: Option<fd_set>, writefds: Option<fd_set>, exceptfds: Option<fd_set>, timeout: Option<timeval> }
    -> c_int + { readfds: Option<fd_set>, writefds: Option<fd_set>, exceptfds: Option<fd_set> }
    ~ [Desc] for [x86_64: 23],
  // semctl: TODO: decode arg
  semctl(semid: c_int, semnum: c_int, cmd: c_int, arg: *mut c_void) / { semid: c_int, semnum: c_int, cmd: c_int } -> c_int
    ~ [IPC] for [x86_64: 66, aarch64: 191, riscv64: 191],
  semget(key: key_t, nsems: c_int, semflg: c_int) / { key: key_t, nsems: c_int, semflg: c_int } -> c_int
    ~ [IPC] for [x86_64: 64, aarch64: 190, riscv64: 190],
  semop(semid: c_int, sops: *mut sembuf, nsops: size_t) / { semid: c_int, nsops: c_uint, sops: Vec<sembuf> @ counted_by(nsops) } -> c_int
    ~ [IPC] for [x86_64: 65, aarch64: 193, riscv64: 193],
  semtimedop(semid: c_int, sops: *mut sembuf, nsops: size_t, timeout: *const timespec) /
    { semid: c_int, nsops: c_uint, sops: Vec<sembuf> @ counted_by(nsops), timeout: Option<timespec> } -> c_int
    ~ [IPC] for [x86_64: 220, aarch64: 192, riscv64: 192],
  // semtimedop_time64
  // send
  sendfile(out_fd: RawFd, in_fd: RawFd, offset: *mut off_t, count: size_t) /
    { out_fd: RawFd, in_fd: RawFd, offset: off_t, count: size_t } -> ssize_t ~ [Desc, Network] for [x86_64: 40, aarch64: 71, riscv64: 71],
  // sendfile64
  sendmmsg(sockfd: RawFd, msgvec: *mut mmsghdr, vlen: c_uint, flags: c_int) /
    { sockfd: RawFd, vlen: c_uint, flags: c_int, msgvec: Vec<mmsghdr> @ counted_by(vlen) } -> c_int
    ~ [Network] for [x86_64: 307, aarch64: 269, riscv64: 269],
  sendmsg(sockfd: RawFd, msg: *const msghdr, flags: c_int) / { sockfd: RawFd, flags: c_int, msg: msghdr } -> ssize_t
    ~ [Network] for [x86_64: 46, aarch64: 211, riscv64: 211],
  sendto(sockfd: RawFd, buf: *const c_void, len: size_t, flags: c_int, dest_addr: *const sockaddr, addrlen: socklen_t) /
    { sockfd: RawFd, buf: Vec<u8> @ counted_by(len), flags: c_int, dest_addr: Option<sockaddr> } -> ssize_t + { }
    ~ [Network] for [x86_64: 44, aarch64: 206, riscv64: 206],
  set_mempolicy(mode: c_int, nodemask: *const c_ulong, maxnode: c_ulong) /
    { mode: c_int,
      nodemask: Vec<c_ulong> @ counted_by( maxnode + (8 * std::mem::size_of::<c_ulong>() - 1) / std::mem::size_of::<c_ulong>() ),
      maxnode: c_ulong }
     -> c_int ~ [Memory] for [x86_64: 238, aarch64: 237, riscv64: 237],
  set_mempolicy_home_node(start: c_ulong, len: c_ulong, home_mode: c_ulong, flags: c_ulong) /
    { start: c_ulong, len: c_ulong, home_mode: c_ulong, flags: c_ulong }
    -> c_int ~ [Memory] for [x86_64: 450, aarch64: 450, riscv64: 450],
  set_robust_list(head: *mut robust_list_head, len: size_t) / { head: AddressType, len: size_t } -> c_long
    ~ [] for [x86_64: 273, aarch64: 99, riscv64: 99],
  set_thread_area(u_info: *mut user_desc) / { u_info: user_desc } -> c_int ~ [] for [x86_64: 205],
  set_tid_address(tidptr: *mut c_int) / { tidptr: AddressType } -> pid_t ~ [] for [x86_64: 218, aarch64: 96, riscv64: 96],
  // setdomainname: FIXME: name doesn't require terminating null.
  setdomainname(name: *const c_char, len: size_t) / { name: CString } -> c_int ~ [] for [x86_64: 171, aarch64: 162, riscv64: 162],
  setfsgid(fsgid: gid_t) / { fsgid: gid_t } -> c_int ~ [Creds] for [x86_64: 123, aarch64: 152, riscv64: 152],
  // setfsgid32
  setfsuid(fsuid: uid_t) / { fsuid: uid_t } -> c_int ~ [Creds] for [x86_64: 122, aarch64: 151, riscv64: 151],
  // setfsuid32
  setgid(gid: gid_t) / { gid: gid_t } -> c_int ~ [Creds] for [x86_64: 106, aarch64: 144, riscv64: 144],
  // setgid32
  setgroups(size: size_t, list: *const gid_t) / { list: Option<Vec<gid_t>> @ counted_by(size) } -> c_int
    ~ [Creds] for [x86_64: 116, aarch64: 159, riscv64: 159],
  // setgroups32
  // sethae
  // sethostname: FIXME: name doesn't require terminating null.
  sethostname(name: *const c_char, len: size_t) / { name: CString, len: size_t } -> c_int
    ~ [] for [x86_64: 170, aarch64: 161, riscv64: 161],
  setitimer(which: c_int, new_value: *const itimerval, old_value: *mut itimerval) /
    { which: c_int, new_value: itimerval, old_value: Option<itimerval> } -> c_int
    ~ [] for [x86_64: 38, aarch64: 103, riscv64: 103],
  setns(fd: RawFd, nstype: c_int) / { fd: RawFd, nstype: c_int } -> c_int ~ [Desc] for [x86_64: 308, aarch64: 268, riscv64: 268],
  setpgid(pid: pid_t, pgid: pid_t) / { pid: pid_t, pgid: pid_t } -> c_int ~ [] for [x86_64: 109, aarch64: 154, riscv64: 154],
  // setpgrp
  setpriority(which: c_int, who: id_t, prio: c_int) / { which: c_int, who: id_t, prio: c_int } -> c_int
    ~ [] for [x86_64: 141, aarch64: 140, riscv64: 140],
  setregid(rgid: gid_t, egid: gid_t) / { rgid: gid_t, egid: gid_t } -> c_int ~ [Creds] for [x86_64: 114, aarch64: 143, riscv64: 143],
  // setregid32
  setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) / { rgid: gid_t, egid: gid_t, sgid: gid_t } -> c_int
    ~ [Creds] for [x86_64: 119, aarch64: 149, riscv64: 149],
  // setresgid32
  setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) / { ruid: uid_t, euid: uid_t, suid: uid_t } -> c_int
    ~ [Creds] for [x86_64: 117, aarch64: 147, riscv64: 147],
  // setresuid32
  setreuid(ruid: uid_t, euid: uid_t) / { ruid: uid_t, euid: uid_t } -> c_int ~ [Creds] for [x86_64: 113, aarch64: 145, riscv64: 145],
  // setreuid32
  setrlimit(resource: c_int, rlim: *const rlimit) / { resource: c_int, rlim: rlimit } -> c_int
    ~ [] for [x86_64: 160, aarch64: 164, riscv64: 164],
  setsid() / {} -> pid_t ~ [] for [x86_64: 112, aarch64: 157, riscv64: 157],
  setsockopt(sockfd: RawFd, level: c_int, optname: c_int, optval: *const c_void, optlen: socklen_t) /
    { sockfd: RawFd, level: c_int, optname: c_int, optval: Vec<u8> @ counted_by(optlen) } -> c_int
    ~ [Network] for [x86_64: 54, aarch64: 208, riscv64: 208],
  settimeofday(tv: *const timeval, tz: *const timezone) / { tv: timeval, tz: Option<timezone> } -> c_int
    ~ [Clock] for [x86_64: 164, aarch64: 170, riscv64: 170],
  setuid(uid: uid_t) / { uid: uid_t } -> c_int ~ [Creds] for [x86_64: 105, aarch64: 146, riscv64: 146],
  // setuid32
  setxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: size_t, flags: c_int) /
    { path: PathBuf, name: CString, value: CString, size: size_t, flags: c_int } -> c_int ~ [File] for [x86_64: 188, aarch64: 5, riscv64: 5],
  // sgetmask
  shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) / { shmid: c_int, shmaddr: AddressType, shmflg: c_int } -> AddressType
    ~ [IPC, Memory] for [x86_64: 30, aarch64: 196, riscv64: 196],
  shmctl(shmid: c_int, cmd: c_int, buf: *mut shmid_ds) / { shmid: c_int, cmd: c_int, buf: shmid_ds } -> c_int
    ~ [IPC] for [x86_64: 31, aarch64: 195, riscv64: 195],
  shmdt(shmaddr: *const c_void) / { shmaddr: AddressType } -> c_int ~ [IPC, Memory] for [x86_64: 67, aarch64: 197, riscv64: 197],
  shmget(key: key_t, size: size_t, shmflg: c_int) / { key: key_t, size: size_t, shmflg: c_int } -> c_int
    ~ [IPC] for [x86_64: 29, aarch64: 194, riscv64: 194],
  shutdown(sockfd: RawFd, how: c_int) / { sockfd: RawFd, how: c_int } -> c_int ~ [Network] for [x86_64: 48, aarch64: 210, riscv64: 210],
  // sigaction
  sigaltstack(ss: *const stack_t, old_ss: *mut stack_t) / { ss: Option<stack_t> } -> c_int + { old_ss: Option<stack_t> }
    ~ [Signal] for [x86_64: 131, aarch64: 132, riscv64: 132],
  // signal
  signalfd(fd: RawFd, mask: *const sigset_t, size: size_t) / { fd: RawFd, mask: sigset_t, size: size_t } -> c_int
    ~ [Desc, Signal] for [x86_64: 282],
  signalfd4(fd: RawFd, mask: *const sigset_t, size: size_t, flags: c_int) / { fd: RawFd, mask: sigset_t, size: size_t, flags: c_int } -> c_int
    ~ [Desc, Signal] for [x86_64: 289, aarch64: 74, riscv64: 74],
  // sigpending
  // sigprocmask
  // sigreturn
  // sigsuspend
  socket(domain: c_int, r#type: c_int, protocol: c_int) / { domain: c_int, r#type: c_int, protocol: c_int } -> RawFd
    ~ [Network] for [x86_64: 41, aarch64: 198, riscv64: 198],
  // socketcall
  socketpair(domain: c_int, r#type: c_int, protocol: c_int, sv: *mut RawFd) /
    { domain: c_int, r#type: c_int, protocol: c_int } -> c_int + { sv: [RawFd;2] }
    ~ [Network] for [x86_64: 53, aarch64: 199, riscv64: 199],
  splice(fd_in: RawFd, off_in: *mut off_t, fd_out: RawFd, off_out: *mut off_t, len: size_t, flags: c_uint) /
    { fd_in: RawFd, off_in: off_t, fd_out: RawFd, off_out: off_t, len: size_t, flags: c_uint } -> ssize_t
    ~ [Desc] for [x86_64: 275, aarch64: 76, riscv64: 76],
  // spu_create
  // spu_run
  // ssetmask
  stat(pathname: *const c_char, statbuf: *mut stat) / { pathname: PathBuf } -> c_int + { statbuf: stat }
    ~ [File, Stat, StatLike] for [x86_64: 4],
  // stat64
  statfs(path: *const c_char, buf: *mut statfs) / { path: PathBuf } -> c_int + { buf: statfs }
    ~ [File, StatFs, StatFsLike] for [x86_64: 137, aarch64: 99, riscv64: 99],
  // statfs64
  // statmount: TODO
  statmount(req: *const mnt_id_req, buf: *mut c_void, bufsize: size_t, flags: c_uint) /
    { req: mnt_id_req, bufsize: size_t, flags: c_uint } -> c_int + { buf: Arc<statmount> }
    ~ [] for [x86_64: 457, aarch64: 457, riscv64: 457],
  statx(dirfd: RawFd, pathname: *const c_char, flags: c_int, mask: c_uint, statxbuf: *mut statx) /
    { dirfd: RawFd, pathname: PathBuf, flags: c_int, mask: c_uint } -> c_int + { statxbuf: statx }
    ~ [Desc, File, FStat, StatLike] for [x86_64: 332, aarch64: 291, riscv64: 291],
  // stime
  // subpage_prot
  // swapcontext
  swapoff(path: *const c_char) / { path: PathBuf } -> c_int ~ [File] for [x86_64: 168, aarch64: 255, riscv64: 255],
  swapon(path: *const c_char, swapflags: c_int) / { path: PathBuf, swapflags: c_int } -> c_int
    ~ [File] for [x86_64: 167, aarch64: 224, riscv64: 224],
  // switch_endian
  symlink(target: *const c_char, linkpath: *const c_char) / { target: PathBuf, linkpath: PathBuf } -> c_int
    ~ [File] for [x86_64: 88],
  symlinkat(target: *const c_char, newdirfd: RawFd, linkpath: *const c_char) /
    { target: PathBuf, newdirfd: RawFd, linkpath: PathBuf } -> c_int
    ~ [Desc, File] for [x86_64: 266, aarch64: 36, riscv64: 36],
  // TODO: sync always returns 0
  sync() / {} -> c_int ~ [] for [x86_64: 162, aarch64: 81, riscv64: 81],
  sync_file_range(fd: RawFd, offset: off_t, nbytes: off_t, flags: c_uint) /
    { fd: RawFd, offset: off_t, nbytes: off_t, flags: c_uint } -> c_int
    ~ [Desc] for [x86_64: 277, aarch64: 84, riscv64: 84],
  // sync_file_range2
  syncfs(fd: RawFd) / { fd: RawFd } -> c_int ~ [Desc] for [x86_64: 306, aarch64: 267, riscv64: 267],
  // sys_debug_setcontext
  // syscall
  sysfs(option: c_int, arg1: c_ulong, arg2: c_ulong) / { option: c_int, arg1: c_ulong, arg2: c_ulong } -> c_int
    ~ [] for [x86_64: 139],
  sysinfo(info: *mut sysinfo) / { } -> c_int + { info: sysinfo } ~ [] for [x86_64: 99, aarch64: 179, riscv64: 179],
  syslog(typ: c_int, buf: *const c_char, len: c_int) / { typ: c_int, buf: CString, len: c_int } -> c_int
    ~ [] for [x86_64: 103, aarch64: 116, riscv64: 116],
  // sysmips
  tee(fd_in: RawFd, fd_out: RawFd, len: size_t, flags: c_uint) / { fd_in: RawFd, fd_out: RawFd, len: size_t, flags: c_uint } -> ssize_t
    ~ [Desc] for [x86_64: 276, aarch64: 77, riscv64: 77],
  tgkill(tgid: pid_t, tid: pid_t, sig: c_int) / { tgid: pid_t, tid: pid_t, sig: c_int } -> c_int
    ~ [Signal, Process] for [x86_64: 234, aarch64: 131, riscv64: 131],
  time(tloc: *mut time_t) / { } -> time_t + { tloc: Option<time_t> } ~ [Clock] for [x86_64: 201],
  timer_create(clockid: clockid_t, sevp: *const sigevent, timerid: *mut timer_t) /
    { clockid: clockid_t, sevp: Option<sigevent> } -> c_int + { timerid: InspectResult<timer_t> }
    ~ [] for [x86_64: 222, aarch64: 107, riscv64: 107],
  timer_delete(timerid: timer_t) / { timerid: timer_t } -> c_int ~ [] for [x86_64: 226, aarch64: 111, riscv64: 111],
  timer_getoverrun(timerid: timer_t) / { timerid: timer_t } -> c_int ~ [] for [x86_64: 225, aarch64: 109, riscv64: 109],
  timer_gettime(timerid: timer_t, curr_value: *mut itimerspec) / { timerid: timer_t } -> c_int + { curr_value: itimerspec }
    ~ [] for [x86_64: 224, aarch64: 108, riscv64: 108],
  // timer_gettime64
  timer_settime(timerid: timer_t, flags: c_int, new_value: *const itimerspec, old_value: *mut itimerspec) /
    { timerid: timer_t, flags: c_int, new_value: itimerspec } -> c_int + { old_value: Option<itimerspec> }
    ~ [] for [x86_64: 223, aarch64: 110, riscv64: 110],
  // timer_settime64
  // timerfd
  timerfd_create(clockid: clockid_t, flags: c_int) / { clockid: clockid_t, flags: c_int } -> RawFd
    ~ [Desc] for [x86_64: 283, aarch64: 85, riscv64: 85],
  timerfd_gettime(fd: RawFd, curr_value: *mut itimerspec) / { fd: RawFd } -> c_int + { curr_value: itimerspec }
    ~ [Desc] for [x86_64: 287, aarch64: 87, riscv64: 87],
  // timerfd_gettime64
  timerfd_settime(fd: RawFd, flags: c_int, new_value: *const itimerspec, old_value: *mut itimerspec) /
    { fd: RawFd, flags: c_int, new_value: itimerspec } -> c_int + { old_value: Option<itimerspec> }
    ~ [Desc] for [x86_64: 286, aarch64: 86, riscv64: 86],
  // timerfd_settime64
  times(buf: *mut tms) / { } -> clock_t + { buf: tms } ~ [] for [x86_64: 100, aarch64: 153, riscv64: 153],
  tkill(tid: pid_t, sig: c_int) / { tid: pid_t, sig: c_int } -> c_int ~ [Signal, Process] for [x86_64: 200, aarch64: 130, riscv64: 130],
  truncate(path: *const c_char, length: off_t) / { path: PathBuf, length: off_t } -> c_int
    ~ [File] for [x86_64: 76, aarch64: 45, riscv64: 45],
  // truncate64
  // ugetrlimit
  umask(mask: mode_t) / { mask: mode_t } -> mode_t ~ [] for [x86_64: 95, aarch64: 166, riscv64: 166],
  // umount
  umount2(target: *const c_char, flags: c_int) / { target: PathBuf, flags: c_int } -> c_int
    ~ [File] for [x86_64: 166, aarch64: 39, riscv64: 39],
  uname(buf: *mut utsname) / { } -> c_int + { buf: utsname } ~ [] for [x86_64: 63, aarch64: 160, riscv64: 160],
  unlink(pathname: *const c_char) / { pathname: PathBuf } -> c_int ~ [File] for [x86_64: 87],
  unlinkat(dirfd: RawFd, pathname: *const c_char, flags: c_int) / { dirfd: RawFd, pathname: PathBuf, flags: c_int } -> c_int
    ~ [Desc, File] for [x86_64: 263, aarch64: 35, riscv64: 35],
  unshare(flags: c_int) / { flags: c_int } -> c_int ~ [] for [x86_64: 272, aarch64: 97, riscv64: 97],
  userfaultfd(flags: c_uint) / { flags: c_uint } -> RawFd ~ [Desc] for [x86_64: 323, aarch64: 282, riscv64: 282],
  ustat(dev: dev_t, ubuf: *mut ustat) / { dev: dev_t } -> c_int + { ubuf: ustat } ~ [] for [x86_64: 136],
  utime(filename: *const c_char, times: *const utimbuf) / { filename: PathBuf, times: Option<utimbuf> } -> c_int
    ~ [File] for [x86_64: 132],
  utimensat(dirfd: RawFd, pathname: *const c_char, times: *const timespec, flags: c_int) /
    { dirfd: RawFd, pathname: PathBuf, times: Option<[timespec; 2]>, flags: c_int } -> c_int
    ~ [Desc, File] for [x86_64: 280, aarch64: 88, riscv64: 88],
  // utimensat_time64
  utimes(filename: *const c_char, times: *const timeval) / { filename: PathBuf, times: Option<[timeval; 2]> } -> c_int
    ~ [File] for [x86_64: 235],
  // utrap_install
  vfork() / {} -> pid_t ~ [Process] for [x86_64: 58],
  vhangup() / {} -> c_int ~ [] for [x86_64: 153, aarch64: 58, riscv64: 58],
  // vm86
  // vm86old
  vmsplice(fd: RawFd, iov: *const iovec, nr_segs: size_t, flags: c_uint) /
    { fd: RawFd, iov: Vec<iovec> @ counted_by(nr_segs), flags: c_uint } -> ssize_t
    ~ [Desc] for [x86_64: 278, aarch64: 75, riscv64: 75],
  wait4(pid: pid_t, wstatus: *mut c_int, options: c_int, rusage: *mut rusage) /
    { pid: pid_t, options: c_int } -> pid_t + { wstatus: InspectResult<c_int>, rusage: Option<rusage> }
    ~ [Process] for [x86_64: 61, aarch64: 260, riscv64: 260],
  waitid(idtype: idtype_t, id: id_t, infop: *mut siginfo_t, options: c_int) /
    { idtype: idtype_t, id: id_t, options: c_int } -> c_int + { infop: Option<siginfo_t> }
    ~ [Process] for [x86_64: 247, aarch64: 95, riscv64: 95],
  // waitpid
  write(fd: RawFd, buf: *const c_void, count: size_t) / { fd: RawFd, buf: Vec<u8> @ counted_by(count) } -> ssize_t
    ~ [Desc] for [x86_64: 1, aarch64: 64, riscv64: 64],
  writev(fd: RawFd, iov: *const iovec, iovcnt: c_int) / { fd: RawFd, iov: Vec<iovec> @ counted_by(iovcnt) } -> ssize_t
    ~ [Desc] for [x86_64: 20, aarch64: 66, riscv64: 66],
}

// pub use cfg_if_has_syscall;

impl SyscallRawArgs {
  /// Get the raw arguments of a syscall on syscall-enter stop.
  ///
  /// Calling this function elsewhere will result in incorrect results or errors.
  pub fn get_on_sysenter(pid: Pid) -> Result<Self, Errno> {
    let regs = ptrace_getregs(pid)?;
    Ok(Self::from_regs(&regs))
  }
}
