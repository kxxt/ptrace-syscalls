use nix::unistd::Pid;

mod syscalls;

pub use syscalls::*;

/// Use ptrace to inspect the process with the given pid and return the inspection result.
///
/// This trait is implemented for syscall args structs intended to be used to gather syscall
/// arguments in ptrace syscall-enter-stop.
pub trait InspectFromPid {
  fn inspect_from(pid: Pid) -> Self;
}

pub trait SyscallNumber {
  fn syscall_number(&self) -> isize;
}
