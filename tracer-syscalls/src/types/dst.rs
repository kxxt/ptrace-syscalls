use std::{alloc::Layout, mem::align_of};

use nix::libc::c_char;
use slice_dst::SliceDst;

#[derive(Debug, PartialEq)]
#[repr(C, align(32))]
// aligned(4 * sizeof(__u64))
pub struct rseq {
  pub cpu_id_start: u32,
  pub cpu_id: u32,
  pub rseq_cs: u64,
  pub flags: u32,
  pub node_id: u32,
  pub mm_cid: u32,
  pub end: [c_char],
}

unsafe impl SliceDst for rseq {
  fn layout_for(len: usize) -> std::alloc::Layout {
    Layout::from_size_align(len, 32).unwrap()
  }

  fn retype(ptr: std::ptr::NonNull<[()]>) -> std::ptr::NonNull<Self> {
    unsafe { std::ptr::NonNull::new_unchecked(ptr.as_ptr() as *mut _) }
  }
}

