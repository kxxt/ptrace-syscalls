use enumflags2::bitflags;

// Keep in-sync with https://github.com/strace/strace/blob/master/src/sysent.h

#[bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyscallGroups {
  /// TF   TRACE_FILE
  /// Trace file-related syscalls.
  File = 0o000000001,
  /// TI   TRACE_IPC
  /// Trace IPC-related syscalls.
  IPC = 0o000000002,
  /// TN   TRACE_NETWORK
  /// Trace network-related syscalls.
  Network = 0o000000004,
  /// TP   TRACE_PROCESS
  /// Trace process-related syscalls.
  Process = 0o000000010,
  /// TS   TRACE_SIGNAL
  /// Trace signal-related syscalls.
  Signal = 0o000000020,
  /// TD   TRACE_DESC
  /// Trace file descriptor-related syscalls.
  Desc = 0o000000040,
  /// TM   TRACE_MEMORY
  /// Trace memory mapping-related syscalls.
  Memory = 0o000000100,
  /// TST  TRACE_STAT
  /// Trace {,*_}{,old}{,x}stat{,64} syscalls.
  Stat = 0o000010000,
  /// TLST TRACE_LSTAT
  /// Trace *lstat* syscalls.
  LStat = 0o000020000,
  /// TSF  TRACE_STATFS
  /// Trace statfs, statfs64, and statvfs syscalls.
  StatFs = 0o000040000,
  /// TFSF TRACE_FSTATFS
  /// Trace fstatfs, fstatfs64 and fstatvfs syscalls.
  FStatFs = 0o000100000,
  /// TSFA TRACE_STATFS_LIKE
  /// Trace statfs-like, fstatfs-like and ustat syscalls.
  StatFsLike = 0o000200000,
  /// TFST TRACE_FSTAT
  /// Trace *fstat{,at}{,64} syscalls.
  FStat = 0o000400000,
  /// TSTA TRACE_STAT_LIKE
  /// Trace *{,l,f}stat{,x,at}{,64} syscalls.
  StatLike = 0o001000000,
  /// PU   TRACE_PURE
  /// Trace getter syscalls with no arguments.
  Pure = 0o002000000,
  /// TC   TRACE_CREDS
  /// Trace process credentials-related syscalls.
  Creds = 0o010000000,
  /// TCL  TRACE_CLOCK
  /// Trace syscalls reading or modifying system clocks.
  Clock = 0o020000000,
}

trait SyscallGroupsGetter {
  fn syscall_groups() -> SyscallGroups;
}
