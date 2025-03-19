pub use bytemuck::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; 32]);

unsafe impl Zeroable for PodScalar {}
unsafe impl Pod for PodScalar {}
