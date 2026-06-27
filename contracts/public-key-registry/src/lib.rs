#![no_std]

use soroban_sdk::{Address, Bytes, Env, contract, contractevent, contractimpl, contracttype};

/// User account registration data
///
/// Used for registering a user's public key to enable encrypted communication
/// for receiving transfers.
/// Not required to interact with the pool. But facilitates in-pool transfers
/// via events. As parties can learn about each other public key.
#[contracttype]
pub struct Account {
    /// Owner address of the account
    pub owner: Address,
    /// X25519 encryption public key for encrypting note data (32 bytes)
    pub encryption_key: Bytes,
    /// BN254 note public key for creating commitments (32 bytes)
    pub note_key: Bytes,
}

/// Event emitted when a user registers their public keys
///
/// This event allows other users to discover keys for sending private
/// transfers. Two key types are required:
/// - encryption_key: X25519 key for encrypting note data (amount, blinding)
/// - note_key: BN254 key for creating commitments in the ZK circuit
#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    /// Address of the account owner
    #[topic]
    pub owner: Address,
    /// X25519 encryption public key
    pub encryption_key: Bytes,
    /// BN254 note public key
    pub note_key: Bytes,
}

/// Auditor's Baby JubJub public key for verifiable selective disclosure.
///
/// `A_pub = a · G` on Baby JubJub (the curve embedded in BN254's scalar field).
/// Senders perform in-circuit ECDH against this key to verifiably encrypt the
/// disclosed note to the auditor. Both coordinates are 32-byte big-endian BN254
/// field elements.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditorKey {
    /// Baby JubJub public key x-coordinate (32 bytes, big-endian)
    pub x: Bytes,
    /// Baby JubJub public key y-coordinate (32 bytes, big-endian)
    pub y: Bytes,
}

/// Event emitted when the auditor registers (or rotates) their Baby JubJub key.
///
/// Lets clients and the auditor tool discover the canonical auditor view key.
#[contractevent]
#[derive(Clone)]
pub struct AuditorKeyEvent {
    /// Address of the auditor that registered the key
    #[topic]
    pub auditor: Address,
    /// Baby JubJub public key x-coordinate (32 bytes, big-endian)
    pub key_x: Bytes,
    /// Baby JubJub public key y-coordinate (32 bytes, big-endian)
    pub key_y: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    Registration(Address),
    /// Single global slot for the auditor's Baby JubJub view key
    Auditor,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Registration {
    encryption_key: Bytes,
    note_key: Bytes,
}

/// Public key registry contract.
///
/// Emits one global registration event stream for user key discovery across
/// all pools in a deployment.
#[contract]
pub struct PublicKeyRegistry;

#[contractimpl]
impl PublicKeyRegistry {
    /// Register a user's public encryption and note keys.
    pub fn register(env: Env, account: Account) {
        account.owner.require_auth();
        assert_eq!(account.encryption_key.len(), 32);
        assert_eq!(account.note_key.len(), 32);

        let key = DataKey::Registration(account.owner.clone());
        let next = Registration {
            encryption_key: account.encryption_key.clone(),
            note_key: account.note_key.clone(),
        };

        if env
            .storage()
            .persistent()
            .get::<DataKey, Registration>(&key)
            == Some(next.clone())
        {
            return;
        }

        env.storage().persistent().set(&key, &next);
        PublicKeyEvent {
            owner: account.owner,
            encryption_key: account.encryption_key,
            note_key: account.note_key,
        }
        .publish(&env);
    }

    /// Register (or rotate) the auditor's Baby JubJub view key.
    ///
    /// Stores the key in the single global auditor slot and emits an
    /// [`AuditorKeyEvent`] for discovery. Requires authorization from the
    /// `auditor` address.
    pub fn register_auditor(env: Env, auditor: Address, key: AuditorKey) {
        auditor.require_auth();
        assert_eq!(key.x.len(), 32);
        assert_eq!(key.y.len(), 32);

        env.storage().persistent().set(&DataKey::Auditor, &key);
        AuditorKeyEvent {
            auditor,
            key_x: key.x,
            key_y: key.y,
        }
        .publish(&env);
    }

    /// Return the registered auditor Baby JubJub view key, if any.
    pub fn auditor_key(env: Env) -> Option<AuditorKey> {
        env.storage().persistent().get(&DataKey::Auditor)
    }
}

#[cfg(test)]
mod test;
