use crate::primitives::{address, Address, U256};
use crate::Database;

const ZERO_BYTE_COST: u64 = 4;
const NON_ZERO_BYTE_COST: u64 = 16;

const TX_L1_COMMIT_EXTRA_COST: U256 = U256::from_limbs([64u64, 0, 0, 0]);
const TX_L1_FEE_PRECISION: U256 = U256::from_limbs([1_000_000_000u64, 0, 0, 0]);

pub const L1_GAS_PRICE_ORACLE_ADDRESS: Address =
    address!("5300000000000000000000000000000000000002");

const L1_BASE_FEE_SLOT: U256 = U256::from_limbs([1u64, 0, 0, 0]);
const L1_OVERHEAD_SLOT: U256 = U256::from_limbs([2u64, 0, 0, 0]);
const L1_SCALAR_SLOT: U256 = U256::from_limbs([3u64, 0, 0, 0]);

/// L1 block info
#[derive(Clone, Debug, Default)]
pub struct L1BlockInfo {
    /// The base fee of the L1 origin block.
    pub l1_base_fee: U256,
    /// The current L1 fee overhead.
    pub l1_fee_overhead: U256,
    /// The current L1 fee scalar.
    pub l1_base_fee_scalar: U256,
}

impl L1BlockInfo {
    /// Try to fetch the L1 block info from the database.
    pub fn try_fetch<DB: Database>(db: &mut DB) -> Result<L1BlockInfo, DB::Error> {
        let l1_base_fee = db.storage(L1_GAS_PRICE_ORACLE_ADDRESS, L1_BASE_FEE_SLOT)?;
        let l1_fee_overhead = db.storage(L1_GAS_PRICE_ORACLE_ADDRESS, L1_OVERHEAD_SLOT)?;
        let l1_base_fee_scalar = db.storage(L1_GAS_PRICE_ORACLE_ADDRESS, L1_SCALAR_SLOT)?;

        Ok(L1BlockInfo {
            l1_base_fee,
            l1_fee_overhead,
            l1_base_fee_scalar,
        })
    }

    /// Calculate the data gas for posting the transaction on L1. Calldata costs 16 gas per non-zero
    /// byte and 4 gas per zero byte.
    pub fn data_gas(&self, input: &[u8]) -> U256 {
        U256::from(input.iter().fold(0, |acc, byte| {
            acc + if *byte == 0x00 {
                ZERO_BYTE_COST
            } else {
                NON_ZERO_BYTE_COST
            }
        }))
    }

    /// Calculate the gas cost of a transaction based on L1 block data posted on L2, depending on the [SpecId] passed.
    pub fn calculate_tx_l1_cost(&self, input: &[u8]) -> U256 {
        let tx_l1_gas = self.data_gas(input);
        tx_l1_gas
            .saturating_add(self.l1_fee_overhead)
            .saturating_add(TX_L1_COMMIT_EXTRA_COST)
            .saturating_mul(self.l1_base_fee)
            .saturating_mul(self.l1_base_fee_scalar)
            .wrapping_div(TX_L1_FEE_PRECISION)
    }
}
