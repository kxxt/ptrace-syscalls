use std::{error::Error, ffi::CString};

use nix::{
  errno::Errno,
  libc::PTRACE_EVENT_EXEC,
  sys::{
    ptrace::{self, traceme},
    signal::{raise, Signal},
    wait::{waitpid, WaitPidFlag, WaitStatus},
  },
  unistd::{execvp, fork, getpid, setpgid, ForkResult, Pid},
};

use ptrace_syscalls::{ptrace_getregs, SyscallRawArgs, SyscallStopInspect};

fn ptrace_syscall(child: Pid, sig: Option<Signal>) -> Result<(), Errno> {
  match ptrace::syscall(child, sig) {
    Err(Errno::ESRCH) => {
      eprintln!("rstrace: warning: child process {child} gone");
      return Ok(());
    }
    r => r?,
  }
  Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = std::env::args_os()
    .skip(1)
    .map(|os| unsafe { CString::from_vec_unchecked(os.into_encoded_bytes()) })
    .collect::<Vec<CString>>();
  if args.is_empty() {
    eprintln!("rstrace: usage: rstrace <program> [args...]");
    return Ok(());
  }
  let program = args[0].clone();
  let child = match unsafe { fork()? } {
    ForkResult::Parent { child } => child,
    ForkResult::Child => {
      let me = getpid();
      setpgid(me, me)?;
      traceme()?;
      raise(Signal::SIGSTOP)?;
      execvp(&program, &args)?;
      return Ok(());
    }
  };
  // wait for child to be stopped by SIGSTOP
  loop {
    let status = waitpid(child, Some(WaitPidFlag::WSTOPPED))?;
    match status {
      WaitStatus::Stopped(_, Signal::SIGSTOP) => {
        break;
      }
      _ => {
        // tracee stopped by other signal, restarting it...
        ptrace::cont(child, None)?;
      }
    }
  }
  let ptrace_opts = {
    use nix::sys::ptrace::Options;
    Options::PTRACE_O_TRACEEXEC
      | Options::PTRACE_O_TRACEEXIT
      | Options::PTRACE_O_EXITKILL
      | Options::PTRACE_O_TRACESYSGOOD
    //   | Options::PTRACE_O_TRACEFORK
    //   | Options::PTRACE_O_TRACECLONE
    //   | Options::PTRACE_O_TRACEVFORK
  };
  ptrace::setoptions(child, ptrace_opts)?;
  // restart the child
  ptrace::syscall(child, None)?;
  let mut counter: usize = 0;
  let mut raw_args: Option<SyscallRawArgs> = None;
  loop {
    let status = waitpid(None, Some(WaitPidFlag::__WALL))?;
    match status {
      WaitStatus::Stopped(pid, sig) => {
        // Deliver the signal to the child
        ptrace_syscall(pid, Some(sig))?;
      }
      WaitStatus::Exited(pid, code) => {
        eprintln!("rstrace: child {pid} exited with code {code}");
        break;
      }
      WaitStatus::Signaled(pid, sig, _) => {
        eprintln!("rstrace: child {pid} signaled with {sig:?}");
        break;
      }
      WaitStatus::PtraceEvent(pid, sig, evt) => match evt {
        PTRACE_EVENT_EXEC => {
          eprintln!("exec: TODO");
          ptrace_syscall(child, None)?;
        }
        _ => ptrace_syscall(child, None)?,
      },
      WaitStatus::PtraceSyscall(pid) => {
        if let Some(raw) = raw_args {
          // syscall-exit-stop
          let regs = ptrace_getregs(pid)?;
          let modified_args = raw.inspect_sysexit(pid, &regs);
          eprintln!("{counter} syscall-exit : {:?}", modified_args);
          counter += 1;
          raw_args = None;
        } else {
          // syscall-enter-stop
          let raw = ptrace_syscalls::get_raw_args(pid)?;
          eprintln!("{counter} syscall-raw  : {:?}", raw);
          let args = raw.inspect_sysenter(pid);
          raw_args = Some(raw);
          eprintln!("{counter} syscall-enter: {:?}", args);
        }
        ptrace_syscall(pid, None)?;
      }
      _ => {}
    }
  }
  Ok(())
}
