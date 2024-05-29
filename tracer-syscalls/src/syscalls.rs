use tracer_syscalls_macros::gen_syscalls;

gen_syscalls! {
  fake 63 { x: i32, y: i32 } for [x86_64, riscv64, aarch64],
  fake_syscall 64 { x: i32, y: i32 } for [x86_64],
}
