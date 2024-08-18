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

// TODO: seccomp-bpf

use owo_colors::OwoColorize;
use ptrace_syscalls::{ptrace_getregs, SyscallModifiedArgs, SyscallRawArgs, SyscallStopInspect};

fn ptrace_syscall(child: Pid, sig: Option<Signal>) -> Result<(), Errno> {
  match ptrace::syscall(child, sig) {
    Err(Errno::ESRCH) => {
      eprintln!("mmaptrace: warning: child process {child} gone");
      return Ok(());
    }
    r => r?,
  }
  Ok(())
}

fn print_maps(pid: Pid, prompt: &str) -> Result<(), Box<dyn Error>> {
  let dashes = "-------------".bright_green();
  eprintln!("{} {} {} {}", dashes, "maps @".bright_green(), prompt.bright_yellow(), dashes);
  let path = format!("/proc/{pid}/maps");
  let content = std::fs::read_to_string(path)?;
  eprint!("{}", content.green());
  eprintln!(
    "{}{}{}",
    "---------------------".bright_green(),
    "-".repeat(prompt.len()).bright_green(),
    "--------------".bright_green()
  );
  Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
  let args = std::env::args_os()
    .skip(1)
    .map(|os| unsafe { CString::from_vec_unchecked(os.into_encoded_bytes()) })
    .collect::<Vec<CString>>();
  if args.is_empty() {
    eprintln!("mmaptrace: usage: mmaptrace <program> [args...]");
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
      WaitStatus::Stopped(_, Signal::SIGSTOP) => break,
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
        eprintln!("mmaptrace: child {pid} exited with code {code}");
        break;
      }
      WaitStatus::Signaled(pid, sig, _) => {
        eprintln!("mmaptrace: child {pid} signaled with {sig:?}");
        break;
      }
      WaitStatus::PtraceEvent(pid, sig, evt) => match evt {
        PTRACE_EVENT_EXEC => {
          ptrace_syscall(child, None)?;
        }
        _ => ptrace_syscall(child, None)?,
      },
      WaitStatus::PtraceSyscall(pid) => {
        if let Some(raw) = raw_args {
          // syscall-exit-stop
          let regs = ptrace_getregs(pid)?;
          let modified_args = raw.inspect_sysexit(pid, &regs);
          if matches!(
            modified_args,
            SyscallModifiedArgs::Mmap(_) | SyscallModifiedArgs::Munmap(_) // | SyscallModifiedArgs::Prctl(_)
          ) {
            counter += 1;
            eprintln!("{} syscall-exit : {:?}", counter.bold().red(), modified_args.bright_magenta());
            print_maps(pid, "sysexit")?;
          }
          raw_args = None;
        } else {
          // syscall-enter-stop
          let raw = ptrace_syscalls::get_raw_args(pid)?;
          if matches!(raw, SyscallRawArgs::Mmap(_) | SyscallRawArgs::Munmap(_)) {
            eprintln!("{} syscall-raw  : {:?}", counter.bold().red(), raw.bright_cyan());
            let args = raw.inspect_sysenter(pid);
            raw_args = Some(raw);
            eprintln!("{} syscall-enter: {:?}", counter.bold().red(), args.bright_cyan());
            print_maps(pid, "sysentr")?;
          }
        }
        ptrace_syscall(pid, None)?;
      }
      _ => {}
    }
  }
  Ok(())
}
