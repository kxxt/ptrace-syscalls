use std::{alloc::Layout, sync::Arc};

use crate::{
  read_remote_memory, AddressType, InspectDynSizedFromPid, InspectError, InspectResult, Pid,
};
use nix::{
  errno::Errno,
  libc::{c_char, c_long},
};
use slice_dst::{SliceDst, TryAllocSliceDst};

macro_rules! impl_slice_dst {
  ($($t:ty => $other:expr, $a:expr),*) => {
    $(
      unsafe impl SliceDst for $t {
        fn layout_for(len: usize) -> std::alloc::Layout {
          Layout::from_size_align(len + $other, $a).unwrap()
        }

        fn retype(ptr: std::ptr::NonNull<[()]>) -> std::ptr::NonNull<Self> {
          unsafe { std::ptr::NonNull::new_unchecked(ptr.as_ptr() as *mut _) }
        }
      }

      impl InspectDynSizedFromPid for InspectResult<Arc<$t>> {
        fn inspect_from(pid: Pid, address: AddressType, size: usize) -> Self {
          let arc = unsafe {
            Arc::<$t>::try_new_slice_dst(size - $other, |ptr| {
              let read = read_remote_memory(pid, address, size, ptr.as_ptr() as AddressType)?;
              if read != size {
                return Err(Errno::EIO);
              } else {
                Ok(())
              }
            })
          }
          .map_err(|e| InspectError::ReadFailure {
            errno: e,
            incomplete: None,
          })?;
          Ok(arc)
        }
      }
    )*
  };
}

impl_slice_dst! {
  rseq => 28, 32,
  statmount => 520, 8,
  msgbuf => std::mem::size_of::<c_long>(), std::mem::align_of::<c_long>()
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

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct msgbuf {
  pub mtype: c_long,
  pub mtext: [c_char],
}
