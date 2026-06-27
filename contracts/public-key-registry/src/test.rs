use super::*;
use soroban_sdk::{
    Address, Bytes, Env,
    testutils::{Address as _, Events as _},
};

fn account(env: &Env, owner: Address, enc_fill: u8, note_fill: u8) -> Account {
    Account {
        owner,
        encryption_key: Bytes::from_array(env, &[enc_fill; 32]),
        note_key: Bytes::from_array(env, &[note_fill; 32]),
    }
}

#[test]
fn register_saves_registration() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner.clone(), 0x11, 0x22);

    env.mock_all_auths();
    client.register(&account);

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(stored.encryption_key, account.encryption_key);
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn duplicate_registration_is_noop() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner.clone(), 0x11, 0x22);

    env.mock_all_auths();
    client.register(&account);
    let events_after_first = env.events().all().events().len();
    client.register(&account);
    let events_after_second = env.events().all().events().len();

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(events_after_first, 1);
    assert_eq!(events_after_second, 0);
    assert_eq!(stored.encryption_key, account.encryption_key);
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn key_rotation_overwrites_registration() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let initial = account(&env, owner.clone(), 0x11, 0x22);
    let rotated = account(&env, owner.clone(), 0x33, 0x44);

    env.mock_all_auths();
    client.register(&initial);
    let first_events = env.events().all().events().len();
    client.register(&rotated);
    let second_events = env.events().all().events().len();

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(first_events, 1);
    assert_eq!(second_events, 1);
    assert_eq!(stored.encryption_key, rotated.encryption_key);
    assert_eq!(stored.note_key, rotated.note_key);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn register_requires_owner_auth() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner, 0x11, 0x22);

    client.register(&account);
}

#[test]
#[should_panic]
fn register_rejects_short_encryption_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = Account {
        owner,
        encryption_key: Bytes::from_slice(&env, &[0x11; 31]),
        note_key: Bytes::from_array(&env, &[0x22; 32]),
    };

    env.mock_all_auths();
    client.register(&account);
}

#[test]
#[should_panic]
fn register_rejects_short_note_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = Account {
        owner,
        encryption_key: Bytes::from_array(&env, &[0x11; 32]),
        note_key: Bytes::from_slice(&env, &[0x22; 31]),
    };

    env.mock_all_auths();
    client.register(&account);
}

// ===== Auditor Baby JubJub key registration (Lumenveil) =====

fn auditor_key(env: &Env, x_fill: u8, y_fill: u8) -> AuditorKey {
    AuditorKey {
        x: Bytes::from_array(env, &[x_fill; 32]),
        y: Bytes::from_array(env, &[y_fill; 32]),
    }
}

#[test]
fn auditor_key_is_none_before_registration() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);

    assert_eq!(client.auditor_key(), None);
}

#[test]
fn register_auditor_saves_and_returns_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let key = auditor_key(&env, 0xAA, 0xBB);

    env.mock_all_auths();
    client.register_auditor(&auditor, &key);

    assert_eq!(client.auditor_key(), Some(key));
}

#[test]
fn register_auditor_emits_event() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let key = auditor_key(&env, 0xAA, 0xBB);

    env.mock_all_auths();
    client.register_auditor(&auditor, &key);

    assert_eq!(env.events().all().events().len(), 1);
}

#[test]
fn register_auditor_overwrites_previous_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let first = auditor_key(&env, 0x11, 0x22);
    let rotated = auditor_key(&env, 0x33, 0x44);

    env.mock_all_auths();
    client.register_auditor(&auditor, &first);
    client.register_auditor(&auditor, &rotated);

    assert_eq!(client.auditor_key(), Some(rotated));
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn register_auditor_requires_auth() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let key = auditor_key(&env, 0xAA, 0xBB);

    client.register_auditor(&auditor, &key);
}

#[test]
#[should_panic]
fn register_auditor_rejects_short_x() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let key = AuditorKey {
        x: Bytes::from_slice(&env, &[0xAA; 31]),
        y: Bytes::from_array(&env, &[0xBB; 32]),
    };

    env.mock_all_auths();
    client.register_auditor(&auditor, &key);
}

#[test]
#[should_panic]
fn register_auditor_rejects_short_y() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);
    let key = AuditorKey {
        x: Bytes::from_array(&env, &[0xAA; 32]),
        y: Bytes::from_slice(&env, &[0xBB; 31]),
    };

    env.mock_all_auths();
    client.register_auditor(&auditor, &key);
}
