use futures::TryFutureExt;
use libc::c_int;
use libc::close;
use libc::fork;
use libc::pid_t;
use libc::siginfo_t;
use libc::ESRCH;
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

extern "C" {
  fn syscall(num: c_int, ...) -> c_int;
}

#[macro_export]
macro_rules! call_syscall {
  ($expr:expr) => {{
    use std::io::Error;
    use std::io::Result;

    match unsafe { $expr } {
      -1 => Result::Err(Error::last_os_error()),
      rc => Result::Ok(rc),
    }
  }};
}

#[macro_export]
macro_rules! retry {
  ($expr:expr) => {{
    loop {
      match $expr {
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
        Err(e) => panic!("{}", e),
        rc => break rc,
      }
    }
  }};
}

const NR_PIDFD_SEND_SIGNAL: c_int = 424;
const NR_PIDFD_OPEN: c_int = 434;

pub type RawPid = pid_t;

/// Wrapper around Linux's `pidfd` which can be used to send signals to the
/// process as well as asynchronously waiting for the process to exit.
#[derive(Debug)]
pub struct PidFd {
  async_fd: AsyncFd<RawFd>,
}

impl AsRawFd for PidFd {
  fn as_raw_fd(&self) -> RawFd {
    self.async_fd.as_raw_fd()
  }
}

impl PidFd {
  /// Creates a new PidFd from a pid.
  pub fn new(pid: RawPid) -> io::Result<Self> {
    let fd = retry!(call_syscall!(syscall(NR_PIDFD_OPEN, pid, 0)))?;

    match AsyncFd::with_interest(fd, Interest::READABLE) {
      Ok(async_fd) => Ok(Self { async_fd }),
      Err(err) => {
        let _ = call_syscall!(close(fd));
        Err(err)
      }
    }
  }

  /// Sends a signal to the process. This function returns `Ok(true)` if the
  /// signal was succesfully delivered, `Ok(false)` if the process has
  /// already exited (posix error `ESRCH`), or `Err(_)` if `kill()` faield for
  /// another reason.
  pub fn kill(&self, sig: c_int) -> io::Result<bool> {
    let fd = self.as_raw_fd();
    let result = call_syscall!(syscall(
      NR_PIDFD_SEND_SIGNAL,
      fd,
      sig,
      null_mut::<siginfo_t>(),
      0
    ));
    match result {
      Ok(_) => Ok(true),
      Err(err) if matches!(err.raw_os_error(), Some(ESRCH)) => Ok(false),
      Err(err) => Err(err),
    }
  }

  /// A future that completes when the process exits. No attempt is made to
  /// reap the process's exit status afterwards, and the pidfd remains open.
  pub async fn wait(&self) -> io::Result<()> {
    self
      .async_fd
      .readable()
      .map_ok(|mut guard| guard.retain_ready())
      .await
  }
}

impl Drop for PidFd {
  fn drop(&mut self) {
    let fd = self.async_fd.as_raw_fd();
    let _ = call_syscall!(close(fd));
  }
}

/// Parses the /proc/meminfo string, returning MemAvailable in kilobytes.
fn parse_mem_avail(meminfo: &str) -> Option<usize> {
  for line in meminfo.lines() {
    let mut parts = line.split_ascii_whitespace();
    if let Some("MemAvailable:") = parts.next() {
      return parts
        .next()
        .and_then(|size_str| size_str.parse::<usize>().ok());
    }
  }
  None
}

/// Returns available memory on the system in bytes.
fn get_mem_avail() -> io::Result<usize> {
  let meminfo = std::fs::read_to_string("/proc/meminfo")?;
  if let Some(size_in_kb) = parse_mem_avail(&meminfo) {
    Ok(size_in_kb * 1024)
  } else {
    Err(io::Error::new(
      ErrorKind::Other,
      "could not parse /proc/meminfo",
    ))
  }
}

#[tokio::main]
async fn main() {
  let mut children = VecDeque::<PidFd>::new();

  while children.len() < 100 {
    let pid = unsafe { fork() };
    if pid == 0 {
      let _waste = vec![1u8; 100 * (1 << 20)];
      let _exit_time = Instant::now() + Duration::from_secs(10);

      #[allow(clippy::clippy::empty_loop)]
      loop {} // Hang.
    }

    eprintln!("child pid: {}", pid);
    let pid_fd = PidFd::new(pid).unwrap();
    children.push_back(pid_fd);
  }

  sleep(Duration::from_secs(5));

  loop {
    eprintln!(
      "children: {}, mem_avail: {}",
      children.len(),
      get_mem_avail().unwrap()
    );

    if let Some(pid_fd) = children.pop_front() {
      pid_fd.kill(libc::SIGKILL).unwrap();
    } else {
      break;
    }
  }

  sleep(Duration::from_secs(5));

  eprintln!("after 5 seconds, mem_avail: {}", get_mem_avail().unwrap());
}
