pub use nix::sys::ptrace::AddressType;
pub use nix::unistd::Pid;

mod arch;
mod group;
mod inspect;
mod syscalls;
pub mod types;

pub use group::*;
pub use inspect::*;
pub use syscalls::*;

pub trait SyscallNumber {
  fn syscall_number(&self) -> isize;
}

/// Get the raw arguments of a syscall on syscall-enter stop.
///
/// Calling this function elsewhere will result in incorrect results or errors.
pub fn get_raw_args(pid: Pid) -> Result<SyscallRawArgs, nix::Error> {
  SyscallRawArgs::get_on_sysenter(pid)
}
