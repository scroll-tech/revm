use crate::{
    b256, B256, BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, BLOB_BASE_FEE_UPDATE_FRACTION_ELECTRA,
    MIN_BLOB_GASPRICE,
};
#[cfg(not(feature = "openvm"))]
pub use alloy_primitives::{keccak256, Keccak256};
#[cfg(feature = "openvm")]
pub use openvm_keccak::*;

/// The Keccak-256 hash of the empty string `""`.
pub const KECCAK_EMPTY: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

#[cfg(feature = "scroll-poseidon-codehash")]
pub const POSEIDON_EMPTY: B256 =
    b256!("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864");

#[cfg(feature = "openvm")]
mod openvm_keccak {
    use alloy_primitives::B256;
    use core::fmt;
    use core::mem::MaybeUninit;

    /// Simple interface to the [`Keccak-256`] hash function.
    ///
    /// [`Keccak-256`]: https://en.wikipedia.org/wiki/SHA-3
    pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> B256 {
        openvm_keccak256_guest::keccak256(bytes.as_ref()).into()
    }

    /// Simple [`Keccak-256`] hasher.
    ///
    /// Note that the "native-keccak" feature is not supported for this struct, and will default to the
    /// [`tiny_keccak`] implementation.
    ///
    /// [`Keccak-256`]: https://en.wikipedia.org/wiki/SHA-3
    #[derive(Clone)]
    pub struct Keccak256 {
        buffer: Vec<u8>,
    }

    impl Default for Keccak256 {
        #[inline]
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for Keccak256 {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Keccak256").finish_non_exhaustive()
        }
    }

    impl Keccak256 {
        /// Creates a new [`Keccak256`] hasher.
        #[inline]
        pub fn new() -> Self {
            Self {
                buffer: Vec::with_capacity(64),
            }
        }

        /// Absorbs additional input. Can be called multiple times.
        #[inline]
        pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
            self.buffer.extend_from_slice(bytes.as_ref());
        }

        /// Pad and squeeze the state.
        #[inline]
        pub fn finalize(self) -> B256 {
            let mut output = MaybeUninit::<B256>::uninit();
            // SAFETY: The output is 32-bytes.
            unsafe { self.finalize_into_raw(output.as_mut_ptr().cast()) };
            // SAFETY: Initialized above.
            unsafe { output.assume_init() }
        }

        /// Pad and squeeze the state into `output`.
        ///
        /// # Panics
        ///
        /// Panics if `output` is not 32 bytes long.
        #[inline]
        #[track_caller]
        pub fn finalize_into(self, output: &mut [u8]) {
            self.finalize_into_array(output.try_into().unwrap())
        }

        /// Pad and squeeze the state into `output`.
        #[inline]
        #[allow(clippy::useless_conversion)]
        pub fn finalize_into_array(self, output: &mut [u8; 32]) {
            openvm_keccak256_guest::set_keccak256(&self.buffer, output);
        }

        /// Pad and squeeze the state into `output`.
        ///
        /// # Safety
        ///
        /// `output` must point to a buffer that is at least 32-bytes long.
        #[inline]
        pub unsafe fn finalize_into_raw(self, output: *mut u8) {
            self.finalize_into_array(&mut *output.cast::<[u8; 32]>())
        }
    }
}

/// Poseidon code hash
#[cfg(feature = "scroll-poseidon-codehash")]
pub fn poseidon(code: &[u8]) -> B256 {
    poseidon_bn254::hash_code(code).into()
}

/// Calculates the `excess_blob_gas` from the parent header's `blob_gas_used` and `excess_blob_gas`.
///
/// See also [the EIP-4844 helpers]<https://eips.ethereum.org/EIPS/eip-4844#helpers>
/// (`calc_excess_blob_gas`).
///
/// EIP-7742: Uncouple blob count between CL and EL
/// Removes hardcoded constants and uses the `target_blob_gas_per_block` from the parent header.
#[inline]
pub fn calc_excess_blob_gas(
    parent_excess_blob_gas: u64,
    parent_blob_gas_used: u64,
    parent_target_blob_gas_per_block: u64,
) -> u64 {
    (parent_excess_blob_gas + parent_blob_gas_used).saturating_sub(parent_target_blob_gas_per_block)
}

/// Calculates the blob gas price from the header's excess blob gas field.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`get_blob_gasprice`).
#[inline]
pub fn calc_blob_gasprice(excess_blob_gas: u64, is_prague: bool) -> u128 {
    fake_exponential(
        MIN_BLOB_GASPRICE,
        excess_blob_gas,
        if is_prague {
            BLOB_BASE_FEE_UPDATE_FRACTION_ELECTRA
        } else {
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
        },
    )
}

/// Approximates `factor * e ** (numerator / denominator)` using Taylor expansion.
///
/// This is used to calculate the blob price.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`fake_exponential`).
///
/// # Panics
///
/// This function panics if `denominator` is zero.
#[inline]
pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u128 {
    assert_ne!(denominator, 0, "attempt to divide by zero");
    let factor = factor as u128;
    let numerator = numerator as u128;
    let denominator = denominator as u128;

    let mut i = 1;
    let mut output = 0;
    let mut numerator_accum = factor * denominator;
    while numerator_accum > 0 {
        output += numerator_accum;

        // Denominator is asserted as not zero at the start of the function.
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += 1;
    }
    output / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GAS_PER_BLOB;

    const TARGET_BLOB_GAS_PER_BLOCK: u64 = 3 * GAS_PER_BLOB;

    // https://github.com/ethereum/go-ethereum/blob/28857080d732857030eda80c69b9ba2c8926f221/consensus/misc/eip4844/eip4844_test.go#L27
    #[test]
    fn test_calc_excess_blob_gas() {
        for t @ &(excess, blobs, expected) in &[
            // The excess blob gas should not increase from zero if the used blob
            // slots are below - or equal - to the target.
            (0, 0, 0),
            (0, 1, 0),
            (0, TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB, 0),
            // If the target blob gas is exceeded, the excessBlobGas should increase
            // by however much it was overshot
            (
                0,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) + 1,
                GAS_PER_BLOB,
            ),
            (
                1,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) + 1,
                GAS_PER_BLOB + 1,
            ),
            (
                1,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) + 2,
                2 * GAS_PER_BLOB + 1,
            ),
            // The excess blob gas should decrease by however much the target was
            // under-shot, capped at zero.
            (
                TARGET_BLOB_GAS_PER_BLOCK,
                TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB,
                TARGET_BLOB_GAS_PER_BLOCK,
            ),
            (
                TARGET_BLOB_GAS_PER_BLOCK,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) - 1,
                TARGET_BLOB_GAS_PER_BLOCK - GAS_PER_BLOB,
            ),
            (
                TARGET_BLOB_GAS_PER_BLOCK,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) - 2,
                TARGET_BLOB_GAS_PER_BLOCK - (2 * GAS_PER_BLOB),
            ),
            (
                GAS_PER_BLOB - 1,
                (TARGET_BLOB_GAS_PER_BLOCK / GAS_PER_BLOB) - 1,
                0,
            ),
        ] {
            let actual =
                calc_excess_blob_gas(excess, blobs * GAS_PER_BLOB, TARGET_BLOB_GAS_PER_BLOCK);
            assert_eq!(actual, expected, "test: {t:?}");
        }
    }

    // https://github.com/ethereum/go-ethereum/blob/28857080d732857030eda80c69b9ba2c8926f221/consensus/misc/eip4844/eip4844_test.go#L60
    #[test]
    fn test_calc_blob_fee() {
        let blob_fee_vectors = &[
            (0, 1),
            (2314057, 1),
            (2314058, 2),
            (10 * 1024 * 1024, 23),
            // calc_blob_gasprice approximates `e ** (excess_blob_gas / BLOB_BASE_FEE_UPDATE_FRACTION)` using Taylor expansion
            //
            // to roughly find where boundaries will be hit:
            // 2 ** bits = e ** (excess_blob_gas / BLOB_BASE_FEE_UPDATE_FRACTION)
            // excess_blob_gas = ln(2 ** bits) * BLOB_BASE_FEE_UPDATE_FRACTION
            (148099578, 18446739238971471609), // output is just below the overflow
            (148099579, 18446744762204311910), // output is just after the overflow
            (161087488, 902580055246494526580),
        ];

        for &(excess, expected) in blob_fee_vectors {
            let actual = calc_blob_gasprice(excess, false);
            assert_eq!(actual, expected, "test: {excess}");
        }
    }

    // https://github.com/ethereum/go-ethereum/blob/28857080d732857030eda80c69b9ba2c8926f221/consensus/misc/eip4844/eip4844_test.go#L78
    #[test]
    fn fake_exp() {
        for t @ &(factor, numerator, denominator, expected) in &[
            (1u64, 0u64, 1u64, 1u128),
            (38493, 0, 1000, 38493),
            (0, 1234, 2345, 0),
            (1, 2, 1, 6), // approximate 7.389
            (1, 4, 2, 6),
            (1, 3, 1, 16), // approximate 20.09
            (1, 6, 2, 18),
            (1, 4, 1, 49), // approximate 54.60
            (1, 8, 2, 50),
            (10, 8, 2, 542), // approximate 540.598
            (11, 8, 2, 596), // approximate 600.58
            (1, 5, 1, 136),  // approximate 148.4
            (1, 5, 2, 11),   // approximate 12.18
            (2, 5, 2, 23),   // approximate 24.36
            (1, 50000000, 2225652, 5709098764),
            (1, 380928, BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, 1),
        ] {
            let actual = fake_exponential(factor, numerator, denominator);
            assert_eq!(actual, expected, "test: {t:?}");
        }
    }
}
