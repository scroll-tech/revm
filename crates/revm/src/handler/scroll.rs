//! Scroll related handlers.
use revm_interpreter::primitives::EVMError;

use crate::{
    interpreter::{return_ok, return_revert, Gas, InstructionResult},
    primitives::{db::Database, Env, Spec, SpecId::LONDON, U256},
    EVMData,
};

/// Handle output of the transaction
pub fn handle_call_return<SPEC: Spec>(
    env: &Env,
    call_result: InstructionResult,
    returned_gas: Gas,
) -> Gas {
    super::mainnet::handle_call_return::<SPEC>(env, call_result, returned_gas)
}

#[inline]
pub fn handle_reimburse_caller<SPEC: Spec, DB: Database>(
    data: &mut EVMData<'_, DB>,
    gas: &Gas,
    gas_refund: u64,
) -> Result<(), EVMError<DB::Error>> {
    super::mainnet::handle_reimburse_caller::<SPEC, DB>(data, gas, gas_refund)
}

/// Reward beneficiary with gas fee.
#[inline]
pub fn reward_beneficiary<SPEC: Spec, DB: Database>(
    data: &mut EVMData<'_, DB>,
    gas: &Gas,
    gas_refund: u64,
) -> Result<(), EVMError<DB::Error>> {
    let beneficiary = data.env.block.coinbase;
    let effective_gas_price = data.env.effective_gas_price();
    let l1_fee = data.env.tx.l1_fee;

    // transfer fee to coinbase/beneficiary.
    // EIP-1559 discard basefee for coinbase transfer. Basefee amount of gas is discarded.
    // let coinbase_gas_price = if SPEC::enabled(LONDON) {
    //     effective_gas_price.saturating_sub(data.env.block.basefee)
    // } else {
    //     effective_gas_price
    // };
    let coinbase_gas_price = effective_gas_price;

    let (coinbase_account, _) = data
        .journaled_state
        .load_account(beneficiary, data.db)
        .map_err(EVMError::Database)?;

    coinbase_account.mark_touch();
    coinbase_account.info.balance = coinbase_account
        .info
        .balance
        .saturating_add(coinbase_gas_price * U256::from(gas.spend() - gas_refund))
        .saturating_add(l1_fee);

    Ok(())
}

/// Calculate gas refund for transaction.
///
/// If config is set to disable gas refund, it will return 0.
///
/// If spec is set to london, it will decrease the maximum refund amount to 5th part of
/// gas spend. (Before london it was 2th part of gas spend)
#[inline]
pub fn calculate_gas_refund<SPEC: Spec>(env: &Env, gas: &Gas) -> u64 {
    super::mainnet::calculate_gas_refund::<SPEC>(env, gas)
}
