//! Handler related to Scroll chain

use crate::handler::mainnet;
use crate::handler::mainnet::deduct_caller_inner;
use crate::{
    handler::register::EvmHandler,
    interpreter::Gas,
    primitives::{
        db::Database, spec_to_generic, EVMError, InvalidTransaction, Spec, SpecId, TransactTo, U256,
    },
    Context,
};
#[cfg(not(feature = "std"))]
use std::string::ToString;
use std::sync::Arc;

pub fn scroll_handle_register<DB: Database, EXT>(handler: &mut EvmHandler<'_, EXT, DB>) {
    spec_to_generic!(handler.cfg.spec_id, {
        // load l1 data
        handler.pre_execution.load_accounts = Arc::new(load_accounts::<SPEC, EXT, DB>);
        // l1_fee is added to the gas cost.
        handler.pre_execution.deduct_caller = Arc::new(deduct_caller::<SPEC, EXT, DB>);
        // basefee is sent to coinbase
        handler.post_execution.reward_beneficiary = Arc::new(reward_beneficiary::<SPEC, EXT, DB>);
    });
}

/// Load account (make them warm) and l1 data from database.
#[inline]
pub fn load_accounts<SPEC: Spec, EXT, DB: Database>(
    context: &mut Context<EXT, DB>,
) -> Result<(), EVMError<DB::Error>> {
    let l1_block_info =
        crate::scroll::L1BlockInfo::try_fetch(&mut context.evm.inner.db, SPEC::SPEC_ID)
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
    let caller_account = context
        .evm
        .inner
        .journaled_state
        .load_account(context.evm.inner.env.tx.caller, &mut context.evm.inner.db)?;

    if !context.evm.inner.env.tx.scroll.is_l1_msg {
        // We deduct caller max balance after minting and before deducing the
        // l1 cost, max values is already checked in pre_validate but l1 cost wasn't.
        deduct_caller_inner::<SPEC>(caller_account.data, &context.evm.inner.env);

        let Some(rlp_bytes) = &context.evm.inner.env.tx.scroll.rlp_bytes else {
            return Err(EVMError::Custom(
                "[SCROLL] Failed to load transaction rlp_bytes.".to_string(),
            ));
        };
        // Deduct l1 fee from caller.
        let tx_l1_cost = context
            .evm
            .inner
            .l1_block_info
            .as_ref()
            .expect("L1BlockInfo should be loaded")
            .calculate_tx_l1_cost(rlp_bytes, SPEC::SPEC_ID);
        if tx_l1_cost.gt(&caller_account.info.balance) {
            return Err(EVMError::Transaction(
                InvalidTransaction::LackOfFundForMaxFee {
                    fee: tx_l1_cost.into(),
                    balance: caller_account.info.balance.into(),
                },
            ));
        }
        caller_account.data.info.balance =
            caller_account.data.info.balance.saturating_sub(tx_l1_cost);
    } else {
        // bump the nonce for calls. Nonce for CREATE will be bumped in `handle_create`.
        if matches!(context.evm.inner.env.tx.transact_to, TransactTo::Call(_)) {
            // Nonce is already checked
            caller_account.data.info.nonce = caller_account.data.info.nonce.saturating_add(1);
        }

        // touch account so we know it is changed.
        caller_account.data.mark_touch();
    }
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

    let coinbase_account = context
        .evm
        .inner
        .journaled_state
        .load_account(beneficiary, &mut context.evm.inner.db)?;

    if !context.evm.inner.env.tx.scroll.is_l1_msg {
        let Some(l1_block_info) = &context.evm.inner.l1_block_info else {
            return Err(EVMError::Custom(
                "[SCROLL] Failed to load L1 block information.".to_string(),
            ));
        };

        let Some(rlp_bytes) = &context.evm.inner.env.tx.scroll.rlp_bytes else {
            return Err(EVMError::Custom(
                "[SCROLL] Failed to load transaction rlp_bytes.".to_string(),
            ));
        };

        let l1_cost = l1_block_info.calculate_tx_l1_cost(rlp_bytes, SPEC::SPEC_ID);

        coinbase_account.data.mark_touch();
        coinbase_account.data.info.balance = coinbase_account
            .data
            .info
            .balance
            .saturating_add(coinbase_gas_price * U256::from(gas.spent() - gas.refunded() as u64))
            .saturating_add(l1_cost);
    }

    Ok(())
}
