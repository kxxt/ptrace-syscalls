use enumflags2::bitflags;

#[bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SyscallGroups {
    /// TD   TRACE_DESC
    Desc,
    /// TF   TRACE_FILE
    File,
    /// TI   TRACE_IPC
    IPC,
    /// TN   TRACE_NETWORK
    Network,
    /// TP   TRACE_PROCESS
    Process,
    /// TS   TRACE_SIGNAL
    Signal,
    /// TM   TRACE_MEMORY
    Memory,
    /// TST  TRACE_STAT
    Stat,
    /// TLST TRACE_LSTAT
    LStat,
    /// TFST TRACE_FSTAT
    FStat,
    /// TSTA TRACE_STAT_LIKE
    StatLike,
    /// TSF	 TRACE_STATFS
    StatFs,
    /// TSFA TRACE_STATFS_LIKE
    StatFsLike,
    /// PU   TRACE_PURE
    Pure,
    /// TC   TRACE_CREDS
    Creds,
    /// TCL  TRACE_CLOCK
    Clock,
}