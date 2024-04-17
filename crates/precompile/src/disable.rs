use crate::{Bytes, PrecompileWithAddress};
use revm_primitives::{Precompile, PrecompileError, PrecompileResult};

pub const RIPEMD160: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0x03),
    Precompile::Standard(disable_run),
);
pub const BLAKE2F: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0x09),
    Precompile::Standard(disable_run),
);
pub const POINT_EVALUATION: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0x0A),
    Precompile::Standard(disable_run),
);

/// Always Out of Gas
pub fn disable_run(_input: &Bytes, _gas_limit: u64) -> PrecompileResult {
    Err(PrecompileError::OutOfGas)
}
