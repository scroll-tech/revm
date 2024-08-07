use crate::{Address, Bytecode, HashMap, B256, KECCAK_EMPTY, U256};
use bitflags::bitflags;
use core::hash::{Hash, Hasher};

#[cfg(feature = "scroll-poseidon-codehash")]
use crate::POSEIDON_EMPTY;

/// EVM State is a mapping from addresses to accounts.
pub type EvmState = HashMap<Address, Account>;

/// Structure used for EIP-1153 transient storage.
pub type TransientStorage = HashMap<(Address, U256), U256>;

/// An account's Storage is a mapping from 256-bit integer keys to [EvmStorageSlot]s.
pub type EvmStorage = HashMap<U256, EvmStorageSlot>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Account {
    /// Balance, nonce, and code.
    pub info: AccountInfo,
    /// Storage cache
    pub storage: EvmStorage,
    /// Account status flags.
    pub status: AccountStatus,
}

// The `bitflags!` macro generates `struct`s that manage a set of flags.
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct AccountStatus: u8 {
        /// When account is loaded but not touched or interacted with.
        /// This is the default state.
        const Loaded = 0b00000000;
        /// When account is newly created we will not access database
        /// to fetch storage values
        const Created = 0b00000001;
        /// If account is marked for self destruction.
        const SelfDestructed = 0b00000010;
        /// Only when account is marked as touched we will save it to database.
        const Touched = 0b00000100;
        /// used only for pre spurious dragon hardforks where existing and empty were two separate states.
        /// it became same state after EIP-161: State trie clearing
        const LoadedAsNotExisting = 0b0001000;
        /// used to mark account as cold
        const Cold = 0b0010000;
    }
}

impl Default for AccountStatus {
    fn default() -> Self {
        Self::Loaded
    }
}

impl Account {
    /// Create new account and mark it as non existing.
    pub fn new_not_existing() -> Self {
        Self {
            info: AccountInfo::default(),
            storage: HashMap::new(),
            status: AccountStatus::LoadedAsNotExisting,
        }
    }

    /// Mark account as self destructed.
    pub fn mark_selfdestruct(&mut self) {
        self.status |= AccountStatus::SelfDestructed;
    }

    /// Unmark account as self destructed.
    pub fn unmark_selfdestruct(&mut self) {
        self.status -= AccountStatus::SelfDestructed;
    }

    /// Is account marked for self destruct.
    pub fn is_selfdestructed(&self) -> bool {
        self.status.contains(AccountStatus::SelfDestructed)
    }

    /// Mark account as touched
    pub fn mark_touch(&mut self) {
        self.status |= AccountStatus::Touched;
    }

    /// Unmark the touch flag.
    pub fn unmark_touch(&mut self) {
        self.status -= AccountStatus::Touched;
    }

    /// If account status is marked as touched.
    pub fn is_touched(&self) -> bool {
        self.status.contains(AccountStatus::Touched)
    }

    /// Mark account as newly created.
    pub fn mark_created(&mut self) {
        self.status |= AccountStatus::Created;
    }

    /// Unmark created flag.
    pub fn unmark_created(&mut self) {
        self.status -= AccountStatus::Created;
    }

    /// Mark account as cold.
    pub fn mark_cold(&mut self) {
        self.status |= AccountStatus::Cold;
    }

    /// Mark account as warm and return true if it was previously cold.
    pub fn mark_warm(&mut self) -> bool {
        if self.status.contains(AccountStatus::Cold) {
            self.status -= AccountStatus::Cold;
            true
        } else {
            false
        }
    }

    /// Is account loaded as not existing from database
    /// This is needed for pre spurious dragon hardforks where
    /// existing and empty were two separate states.
    pub fn is_loaded_as_not_existing(&self) -> bool {
        self.status.contains(AccountStatus::LoadedAsNotExisting)
    }

    /// Is account newly created in this transaction.
    pub fn is_created(&self) -> bool {
        self.status.contains(AccountStatus::Created)
    }

    /// Is account empty, check if nonce and balance are zero and code is empty.
    pub fn is_empty(&self) -> bool {
        self.info.is_empty()
    }

    /// Returns an iterator over the storage slots that have been changed.
    ///
    /// See also [EvmStorageSlot::is_changed]
    pub fn changed_storage_slots(&self) -> impl Iterator<Item = (&U256, &EvmStorageSlot)> {
        self.storage.iter().filter(|(_, slot)| slot.is_changed())
    }
}

impl From<AccountInfo> for Account {
    fn from(info: AccountInfo) -> Self {
        Self {
            info,
            storage: HashMap::new(),
            status: AccountStatus::Loaded,
        }
    }
}

/// This type keeps track of the current value of a storage slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvmStorageSlot {
    /// Original value of the storage slot.
    pub original_value: U256,
    /// Present value of the storage slot.
    pub present_value: U256,
    /// Represents if the storage slot is cold.
    pub is_cold: bool,
}

impl EvmStorageSlot {
    /// Creates a new _unchanged_ `EvmStorageSlot` for the given value.
    pub fn new(original: U256) -> Self {
        Self {
            original_value: original,
            present_value: original,
            is_cold: false,
        }
    }

    /// Creates a new _changed_ `EvmStorageSlot`.
    pub fn new_changed(original_value: U256, present_value: U256) -> Self {
        Self {
            original_value,
            present_value,
            is_cold: false,
        }
    }
    /// Returns true if the present value differs from the original value
    pub fn is_changed(&self) -> bool {
        self.original_value != self.present_value
    }

    /// Returns the original value of the storage slot.
    pub fn original_value(&self) -> U256 {
        self.original_value
    }

    /// Returns the current value of the storage slot.
    pub fn present_value(&self) -> U256 {
        self.present_value
    }

    /// Marks the storage slot as cold.
    pub fn mark_cold(&mut self) {
        self.is_cold = true;
    }

    /// Marks the storage slot as warm and returns a bool indicating if it was previously cold.
    pub fn mark_warm(&mut self) -> bool {
        core::mem::replace(&mut self.is_cold, false)
    }
}

/// AccountInfo account information.
#[derive(Clone, Debug, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountInfo {
    /// Account balance.
    pub balance: U256,
    /// Account nonce.
    pub nonce: u64,
    #[cfg(feature = "scroll")]
    /// code size,
    pub code_size: usize,
    /// code hash,
    pub code_hash: B256,
    #[cfg(feature = "scroll-poseidon-codehash")]
    /// keccak code hash,
    pub keccak_code_hash: B256,
    /// code: if None, `code_by_hash` will be used to fetch it if code needs to be loaded from
    /// inside of `revm`.
    pub code: Option<Bytecode>,
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            balance: U256::ZERO,
            #[cfg(feature = "scroll")]
            code_size: 0,
            #[cfg(not(feature = "scroll-poseidon-codehash"))]
            code_hash: KECCAK_EMPTY,
            #[cfg(feature = "scroll-poseidon-codehash")]
            code_hash: POSEIDON_EMPTY,
            #[cfg(feature = "scroll-poseidon-codehash")]
            keccak_code_hash: KECCAK_EMPTY,
            code: Some(Bytecode::default()),
            nonce: 0,
        }
    }
}

impl PartialEq for AccountInfo {
    #[allow(clippy::let_and_return)]
    fn eq(&self, other: &Self) -> bool {
        let eq = self.balance == other.balance
            && self.nonce == other.nonce
            && self.code_hash == other.code_hash;

        #[cfg(all(debug_assertions, feature = "scroll"))]
        if eq {
            assert_eq!(self.code_size, other.code_size);
            #[cfg(feature = "scroll-poseidon-codehash")]
            assert_eq!(self.keccak_code_hash, other.keccak_code_hash);
        }
        eq
    }
}

impl Hash for AccountInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.balance.hash(state);
        self.nonce.hash(state);
        self.code_hash.hash(state);
    }
}

impl AccountInfo {
    pub fn new(
        balance: U256,
        nonce: u64,
        code_hash: B256,
        #[cfg(feature = "scroll-poseidon-codehash")] keccak_code_hash: B256,
        code: Bytecode,
    ) -> Self {
        Self {
            balance,
            nonce,
            #[cfg(feature = "scroll")]
            code_size: code.len(),
            code: Some(code),
            code_hash,
            #[cfg(feature = "scroll-poseidon-codehash")]
            keccak_code_hash,
        }
    }

    /// Returns account info without the code.
    pub fn without_code(mut self) -> Self {
        self.take_bytecode();
        self
    }

    /// Returns if an account is empty.
    ///
    /// An account is empty if the following conditions are met.
    /// - code hash is zero or set to the Keccak256 hash of the empty string `""`
    /// - balance is zero
    /// - nonce is zero
    pub fn is_empty(&self) -> bool {
        let code_empty = self.is_empty_code_hash() || self.code_hash == B256::ZERO;

        #[cfg(all(feature = "scroll", debug_assertions))]
        if code_empty {
            assert_eq!(
                self.code_size, 0,
                "code size should be zero if code hash is empty"
            );
        }

        code_empty && self.balance == U256::ZERO && self.nonce == 0
    }

    /// Returns `true` if the account is not empty.
    pub fn exists(&self) -> bool {
        !self.is_empty()
    }

    /// Returns `true` if account has no nonce and code.
    pub fn has_no_code_and_nonce(&self) -> bool {
        self.is_empty_code_hash() && self.nonce == 0
    }

    /// Return bytecode hash associated with this account.
    /// If account does not have code,
    #[cfg_attr(
        not(feature = "scroll-poseidon-codehash"),
        doc = "it return's `KECCAK_EMPTY` hash."
    )]
    #[cfg_attr(
        feature = "scroll-poseidon-codehash",
        doc = "it return's `POSEIDON_EMPTY` hash."
    )]
    pub fn code_hash(&self) -> B256 {
        self.code_hash
    }

    /// Return keccak code hash associated with this account.
    /// If account does not have code, it return's `KECCAK_EMPTY` hash.
    #[cfg(feature = "scroll-poseidon-codehash")]
    pub fn keccak_code_hash(&self) -> B256 {
        self.keccak_code_hash
    }

    /// Returns true if the code hash is the Keccak256 hash of the empty string `""`.
    #[inline]
    pub fn is_empty_code_hash(&self) -> bool {
        cfg_if::cfg_if! {
            if #[cfg(feature = "scroll-poseidon-codehash")] {
                #[cfg(debug_assertions)]
                if self.code_hash == POSEIDON_EMPTY {
                    assert_eq!(self.code_size, 0);
                    assert_eq!(self.keccak_code_hash, KECCAK_EMPTY);
                }

                self.code_hash == POSEIDON_EMPTY
            } else {
                self.code_hash == KECCAK_EMPTY
            }
        }
    }

    /// Take bytecode from account. Code will be set to None.
    pub fn take_bytecode(&mut self) -> Option<Bytecode> {
        self.code.take()
    }

    /// Set code and its hash to the account.
    pub fn set_code_with_hash(
        &mut self,
        code: Bytecode,
        hash: B256,
        #[cfg(feature = "scroll-poseidon-codehash")] keccak_code_hash: B256,
    ) {
        #[cfg(feature = "scroll")]
        {
            self.code_size = code.len();
            #[cfg(feature = "scroll-poseidon-codehash")]
            {
                self.keccak_code_hash = keccak_code_hash;
            }
        }

        self.code = Some(code);
        self.code_hash = hash;
    }

    /// Re-hash the code, set to empty if code is None,
    /// otherwise update the code hash.
    pub fn set_code_rehash_slow(&mut self, code: Option<Bytecode>) {
        match code {
            Some(code) => {
                self.code_hash = code.hash_slow();
                #[cfg(feature = "scroll")]
                {
                    self.code_size = code.len();
                    #[cfg(feature = "scroll-poseidon-codehash")]
                    {
                        self.keccak_code_hash = code.keccak_hash_slow();
                    }
                }

                self.code = Some(code);
            }
            None => {
                self.code_hash = KECCAK_EMPTY;

                #[cfg(feature = "scroll")]
                {
                    self.code_size = 0;
                    #[cfg(feature = "scroll-poseidon-codehash")]
                    {
                        self.code_hash = POSEIDON_EMPTY;
                        self.keccak_code_hash = KECCAK_EMPTY;
                    }
                }

                self.code = None;
            }
        }
    }

    pub fn from_balance(balance: U256) -> Self {
        AccountInfo {
            balance,
            ..Default::default()
        }
    }

    pub fn from_bytecode(bytecode: Bytecode) -> Self {
        let code_hash = bytecode.hash_slow();
        cfg_if::cfg_if! {
            if #[cfg(not(feature = "scroll"))] {
                AccountInfo {
                    balance: U256::ZERO,
                    nonce: 1,
                    code: Some(bytecode),
                    code_hash,
                }
            } else {
                let code_size = bytecode.len();
                #[cfg(feature = "scroll-poseidon-codehash")]
                let keccak_code_hash = bytecode.keccak_hash_slow();

                AccountInfo {
                    balance: U256::ZERO,
                    nonce: 1,
                    code_size,
                    code: Some(bytecode),
                    code_hash,
                    #[cfg(feature = "scroll-poseidon-codehash")]
                    keccak_code_hash,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Account, U256};

    #[test]
    fn account_is_empty_balance() {
        let mut account = Account::default();
        assert!(account.is_empty());

        account.info.balance = U256::from(1);
        assert!(!account.is_empty());

        account.info.balance = U256::ZERO;
        assert!(account.is_empty());
    }

    #[test]
    fn account_is_empty_nonce() {
        let mut account = Account::default();
        assert!(account.is_empty());

        account.info.nonce = 1;
        assert!(!account.is_empty());

        account.info.nonce = 0;
        assert!(account.is_empty());
    }

    #[test]
    fn account_is_empty_code_hash() {
        let mut account = Account::default();
        assert!(account.is_empty());

        account.info.code_hash = [1; 32].into();
        assert!(!account.is_empty());

        account.info.code_hash = [0; 32].into();
        assert!(account.is_empty());

        cfg_if::cfg_if! {
            if #[cfg(feature = "scroll-poseidon-codehash")] {
                account.info.code_hash = crate::POSEIDON_EMPTY;
            } else {
                account.info.code_hash = crate::KECCAK_EMPTY;
            }
        }
        assert!(account.is_empty());
    }

    #[test]
    fn account_state() {
        let mut account = Account::default();

        assert!(!account.is_touched());
        assert!(!account.is_selfdestructed());

        account.mark_touch();
        assert!(account.is_touched());
        assert!(!account.is_selfdestructed());

        account.mark_selfdestruct();
        assert!(account.is_touched());
        assert!(account.is_selfdestructed());

        account.unmark_selfdestruct();
        assert!(account.is_touched());
        assert!(!account.is_selfdestructed());
    }

    #[test]
    fn account_is_cold() {
        let mut account = Account::default();

        // Account is not cold by default
        assert!(!account.status.contains(crate::AccountStatus::Cold));

        // When marking warm account as warm again, it should return false
        assert!(!account.mark_warm());

        // Mark account as cold
        account.mark_cold();

        // Account is cold
        assert!(account.status.contains(crate::AccountStatus::Cold));

        // When marking cold account as warm, it should return true
        assert!(account.mark_warm());
    }
}
