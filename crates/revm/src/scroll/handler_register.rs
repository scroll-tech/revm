//! Handler related to Scroll chain

use crate::handler::mainnet;
use crate::handler::mainnet::deduct_caller_inner;
use crate::primitives::InvalidTransaction;
use crate::{
    handler::register::EvmHandler,
    interpreter::Gas,
    precompile::Precompiles,
    primitives::{db::Database, spec_to_generic, EVMError, Spec, SpecId, U256},
    Context, ContextPrecompiles,
};
use revm_precompile::PrecompileSpecId;
use std::sync::Arc;

pub fn scroll_handle_register<DB: Database, EXT>(handler: &mut EvmHandler<'_, EXT, DB>) {
    spec_to_generic!(handler.cfg.spec_id, {
        // load precompiles
        handler.pre_execution.load_precompiles = Arc::new(load_precompiles::<SPEC, DB>);
        // load l1 data
        handler.pre_execution.load_accounts = Arc::new(load_accounts::<SPEC, EXT, DB>);
        // l1_fee is added to the gas cost.
        handler.pre_execution.deduct_caller = Arc::new(deduct_caller::<SPEC, EXT, DB>);
        // basefee is sent to coinbase
        handler.post_execution.reward_beneficiary = Arc::new(reward_beneficiary::<SPEC, EXT, DB>);
    });
}

/// Main precompile load
#[inline]
pub fn load_precompiles<SPEC: Spec, DB: Database>() -> ContextPrecompiles<DB> {
    Precompiles::scroll(PrecompileSpecId::from_spec_id(SPEC::SPEC_ID))
        .clone()
        .into()
}

/// Load account (make them warm) and l1 data from database.
#[inline]
pub fn load_accounts<SPEC: Spec, EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
) -> Result<(), EVMError<DB::Error>> {
    let l1_block_info = crate::scroll::L1BlockInfo::try_fetch(&mut context.evm.inner.db)
        .map_err(EVMError::Database)?;
    context.evm.inner.l1_block_info = Some(l1_block_info);

    mainnet::load_accounts::<SPEC, EXT, DB>(context)
}

/// Deducts the caller balance to the transaction limit.
#[inline]
pub fn deduct_caller<SPEC: Spec, EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
) -> Result<(), EVMError<DB::Error>> {
    // load caller's account.
    let (caller_account, _) = context
        .evm
        .inner
        .journaled_state
        .load_account(context.evm.inner.env.tx.caller, &mut context.evm.inner.db)?;

    // We deduct caller max balance after minting and before deducing the
    // l1 cost, max values is already checked in pre_validate but l1 cost wasn't.
    deduct_caller_inner::<SPEC>(caller_account, &context.evm.inner.env);

    // Deduct l1 fee from caller.
    let tx_l1_cost = context
        .evm
        .inner
        .l1_block_info
        .as_ref()
        .expect("L1BlockInfo should be loaded")
        .calculate_tx_l1_cost(&context.evm.inner.env.tx.data);
    if tx_l1_cost.gt(&caller_account.info.balance) {
        return Err(EVMError::Transaction(
            InvalidTransaction::LackOfFundForMaxFee {
                fee: tx_l1_cost.into(),
                balance: caller_account.info.balance.into(),
            },
        ));
    }
    caller_account.info.balance = caller_account.info.balance.saturating_sub(tx_l1_cost);
    Ok(())
}

/// Reward beneficiary with gas fee.
#[inline]
pub fn reward_beneficiary<SPEC: Spec, EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
    gas: &Gas,
) -> Result<(), EVMError<DB::Error>> {
    let beneficiary = context.evm.env.block.coinbase;
    let effective_gas_price = context.evm.env.effective_gas_price();

    // transfer fee to coinbase/beneficiary.
    let coinbase_gas_price = effective_gas_price;

    let (coinbase_account, _) = context
        .evm
        .inner
        .journaled_state
        .load_account(beneficiary, &mut context.evm.inner.db)?;

    let Some(l1_block_info) = &context.evm.inner.l1_block_info else {
        return Err(EVMError::Custom(
            "[SCROLL] Failed to load L1 block information.".to_string(),
        ));
    };

    let l1_cost = l1_block_info.calculate_tx_l1_cost(&context.evm.inner.env.tx.data);

    coinbase_account.mark_touch();
    coinbase_account.info.balance = coinbase_account
        .info
        .balance
        .saturating_add(coinbase_gas_price * U256::from(gas.spent() - gas.refunded() as u64))
        .saturating_add(l1_cost);

    Ok(())
}
