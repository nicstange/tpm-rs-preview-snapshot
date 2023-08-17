extern crate alloc;
use alloc::sync::Arc;

use crate::interface;

#[cfg(feature = "use_allocator_api")]
#[inline(always)]
pub fn arc_try_new<T>(v: T) -> Result<Arc<T>, interface::TpmErr> {
    Arc::try_new(v).map_err(|_| tpm_err_rc!(MEMORY))?
}

#[cfg(not(feature = "use_allocator_api"))]
#[inline(always)]
pub fn arc_try_new<T>(v: T) -> Result<Arc<T>, interface::TpmErr> {
    Ok(Arc::new(v))
}
