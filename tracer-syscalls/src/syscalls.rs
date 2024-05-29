use std::{ffi::CString, os::fd::RawFd};

use nix::unistd::Pid;
use tracer_syscalls_macros::gen_syscalls;

use crate::{
  arch::{syscall_arg, syscall_no_from_regs, PtraceRegisters},
  FromInspectingRegs, SyscallNumber,
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
  fake 63 { pub x: i32, y: i32 } for [x86_64, riscv64, aarch64],
  fake_syscall 64 { x: RawFd, y: CString } for [x86_64],
}
