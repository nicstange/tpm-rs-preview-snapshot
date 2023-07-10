use super::{ReseedableRngCore, RngCore, RngGenerateError, RngReseedFromParentError};
use crate::crypto::io_slices;

pub struct ChainedRng<P: RngCore, C: RngCore + ReseedableRngCore> {
    parent: P,
    child: C,
}

impl<P: RngCore, C: RngCore + ReseedableRngCore> ChainedRng<P, C> {
    pub fn chain(parent: P, child: C) -> Self {
        Self { parent, child }
    }
}

impl<P: RngCore, C: RngCore + ReseedableRngCore> RngCore for ChainedRng<P, C> {
    fn generate(
        &mut self,
        output: &mut io_slices::IoSlicesMut,
        additional_input: Option<&io_slices::IoSlices>,
    ) -> Result<(), RngGenerateError> {
        // The child's generate() can get called multiple times in case a reseed is
        // required. Thus, the original additional_input must not get consumed
        // on the first iteration, make a clone.
        while !output.is_empty() {
            match self.child.generate(output, additional_input) {
                Ok(()) => (),
                Err(RngGenerateError::ReseedRequired) => {
                    self.child
                        .reseed_from_parent(&mut self.parent, None)
                        .map_err(|e| match e {
                            RngReseedFromParentError::ParentGenerateFailure(_) => {
                                RngGenerateError::TpmErr(tpm_err_rc!(FAILURE))
                            }
                            RngReseedFromParentError::TpmErr(e) => RngGenerateError::TpmErr(e),
                        })?;
                }
                Err(e) => {
                    return Err(e);
                }
            };
        }
        Ok(())
    }
}
