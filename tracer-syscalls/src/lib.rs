pub use nix::unistd::Pid;
pub use nix::sys::ptrace::AddressType;

mod arch;
mod inspect;
mod syscalls;
mod group;
pub mod types;

pub use inspect::*;
pub use syscalls::*;
pub use group::*;

pub trait SyscallNumber {
  fn syscall_number(&self) -> isize;
}
