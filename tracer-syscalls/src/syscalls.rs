use tracer_syscalls_macros::gen_syscalls;

use crate::SyscallNumber;

#[derive(Debug, Clone, PartialEq)]
pub struct UnknownArgs {
  pub number: isize,
  pub args: [isize; 6],
}

impl SyscallNumber for UnknownArgs {
  fn syscall_number(&self) -> isize {
    self.number
  }
}

gen_syscalls! {
  fake 63 { pub x: i32, y: i32 } for [x86_64, riscv64, aarch64],
  fake_syscall 64 { x: i32, y: i32 } for [x86_64],
}
