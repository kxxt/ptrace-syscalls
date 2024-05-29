pub use nix::unistd::Pid;
pub use nix::sys::ptrace::AddressType;

mod arch;
mod inspect;
mod syscalls;

pub use inspect::*;
pub use syscalls::*;

pub trait SyscallNumber {
  fn syscall_number(&self) -> isize;
}
