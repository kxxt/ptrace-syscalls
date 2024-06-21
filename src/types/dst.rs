use std::{alloc::Layout, mem::align_of};

use nix::libc::c_char;
use slice_dst::SliceDst;

macro_rules! impl_slice_dst {
  ($($t:ty => $a:literal),*) => {
    $(
      unsafe impl SliceDst for $t {
        fn layout_for(len: usize) -> std::alloc::Layout {
          Layout::from_size_align(len, $a).unwrap()
        }

        fn retype(ptr: std::ptr::NonNull<[()]>) -> std::ptr::NonNull<Self> {
          unsafe { std::ptr::NonNull::new_unchecked(ptr.as_ptr() as *mut _) }
        }
      }
    )*
  };
}

impl_slice_dst! {
  rseq => 32,
  statmount => 8
}

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

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct statmount {
  pub size: u32,
  pub __spare1: u32,
  pub mask: u64,
  pub sb_dev_major: u32,
  pub sb_dev_minor: u32,
  pub sb_magic: u64,
  pub sb_flags: u32,
  pub fs_type: u32,
  pub mnt_id: u64,
  pub mnt_parent_id: u64,
  pub mnt_id_old: u64,
  pub mnt_parent_id_old: u64,
  pub mnt_attr: u64,
  pub mnt_propagation: u64,
  pub mnt_peer_group: u64,
  pub mnt_master: u64,
  pub propagate_from: u64,
  pub mnt_root: u32,
  pub mnt_point: u32,
  pub __spare2: [u64; 50],
  pub str: [c_char],
}
