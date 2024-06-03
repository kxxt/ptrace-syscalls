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
