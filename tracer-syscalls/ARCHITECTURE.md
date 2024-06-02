# Architecture

## Syscalls

### syscall-enter

Copy raw syscall arguments into SyscallRawArgs struct.

Optionally, the tracer decodes the SyscallRawArgs struct into an Args struct by inspecting the tracee(using SyscallEnterInspect trait).

### syscall-exit

The tracer provides the RawArgs struct to decode it into SyscallResult by inspecting the tracee(using SyscallExitInspect trait).

The SyscallResult contains the syscall result(for non-exec syscalls) and modified syscall args.

### Seccomp

A bitflags enum is provided for syscalls. The user can generate a seccomp filter for usage in a follow-fork(or recursive)
tracer based on the syscalls of interest.


### Syscall Groups

The syscall groups are defined by strace: https://unix.stackexchange.com/questions/293090/strace-syscall-classes
It is also a bitflags enum.



