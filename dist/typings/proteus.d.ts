import * as CBOR from 'wire-webapp-cbor';

export declare module derived {
  class CipherKey {
    constructor();

    key: Uint8Array;

    static decode(d: CBOR.Decoder): derived.CipherKey;
    decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    encrypt(plaintext: ArrayBuffer|string|Uint8Array, nonce: Uint8Array): Uint8Array;
    static new(key: Uint8Array): derived.MacKey;
  }

  interface InitialDerivedSecrets extends derived.DerivedSecrets {
    head_key: derived.HeadKey;
  }

  class DerivedSecrets {
    constructor();

    cipher_key: derived.CipherKey;
    mac_key: derived.MacKey;
    next_head_key: derived.HeadKey;

    static kdf(input: Array<number>, salt: Uint8Array, info: string): derived.DerivedSecrets;
    static kdf_init(input: Array<number>, salt: Uint8Array, info: string): derived.InitialDerivedSecrets;
    static kdf_without_salt(input: Array<number>, info: string): derived.InitialDerivedSecrets;
  }

  class HeadKey {
    constructor();

    key: Uint8Array;

    static decode(d: CBOR.Decoder): derived.HeadKey;
    decrypt(encrypted_header: Uint8Array, nonce: Uint8Array): Uint8Array;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    encrypt(header: ArrayBuffer, nonce: Uint8Array): Uint8Array;
    static index_as_nonce(idx: number): Uint8Array;
    static new(key: Uint8Array): derived.HeadKey;

  }

  class MacKey {
    constructor();

    key: Uint8Array;

    static decode(d: CBOR.Decoder): derived.MacKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(key: Uint8Array): derived.MacKey;
    sign(msg: string|Uint8Array): Uint8Array;
    verify(signature: Uint8Array, msg: Uint8Array): boolean;
  }
}

export declare module errors {
  class DecodeError extends ProteusError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class DecryptError extends ProteusError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class DontCallConstructor extends ProteusError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class HeaderDecryptionFailed extends DecryptError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class InputError extends ProteusError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class InvalidHeader extends DecryptError {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }

  class ProteusError extends Error {
    constructor(message?: string, code?: string);
    code: string;
    message: string;
  }
}

export declare module keys {
  class IdentityKey {
    constructor();

    public_key: keys.PublicKey;

    static decode(d: CBOR.Decoder): keys.IdentityKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    fingerprint(): string;
    static new(public_key: keys.PublicKey): keys.IdentityKey;
    toString(): string;
  }

  class IdentityKeyPair {
    constructor();

    public_key: keys.IdentityKey;
    secret_key: keys.SecretKey;
    version: number;

    static decode(d: CBOR.Decoder): keys.IdentityKeyPair;
    static deserialise(buf: ArrayBuffer): keys.IdentityKeyPair;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(): keys.IdentityKeyPair;
    serialise(): ArrayBuffer;
  }

  class KeyPair {
    constructor();

    secret_key: keys.SecretKey;
    public_key: keys.PublicKey;

    private _construct_private_key(ed25519_key_pair: Object): keys.SecretKey;
    private _construct_public_key(ed25519_key_pair: Object): keys.PublicKey;
    static decode(d: CBOR.Decoder): keys.KeyPair;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(): keys.KeyPair;
  }

  class PreKey {
    constructor();

    key_id: number;
    key_pair: keys.KeyPair;
    static MAX_PREKEY_ID: number;
    version: number;

    static decode(d: CBOR.Decoder): keys.PreKey;
    static deserialise(buf: ArrayBuffer): keys.PreKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static generate_prekeys(start: number, size: number): Array<keys.PreKey>;
    static last_resort(): keys.PreKey;
    static new(pre_key_id: number): keys.PreKey;
    serialise(): ArrayBuffer;
  }

  type PreKeyAuth = 'Invalid' | 'Unknown' | 'Valid';

  class PreKeyBundle {
    constructor();

    identity_key:  keys.IdentityKey;
    prekey_id: number;
    public_key: keys.PublicKey;
    signature: Uint8Array;
    version: number;

    static decode(d: CBOR.Decoder): keys.PreKeyBundle;
    static deserialise(buf: ArrayBuffer): keys.PreKeyBundle;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(identity_key: keys.IdentityKey, prekey: keys.PreKey): keys.PreKeyBundle;
    serialise(): ArrayBuffer;
    serialised_json(): {id: number, key: string};
    static signed(identity_key: keys.IdentityKeyPair, prekey: keys.PreKey): keys.PreKeyBundle;
    verify(): keys.PreKeyAuth;
  }

  class PublicKey {
    constructor();

    pub_curve: Uint8Array;
    pub_edward: Uint8Array;

    static decode(d: CBOR.Decoder): keys.PublicKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    fingerprint(): string;
    static new(pub_edward: Uint8Array, pub_curve: Uint8Array): keys.PublicKey;
    verify(signature: Uint8Array, message: string): boolean;
  }

  class SecretKey {
    constructor();

    sec_curve: Uint8Array;
    sec_edward: Uint8Array;

    static decode(d: CBOR.Decoder): keys.SecretKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    shared_secret(public_key: keys.PublicKey): Uint8Array;
    sign(message: string): Uint8Array;
    static new(pub_edward: Uint8Array, pub_curve: Uint8Array): keys.SecretKey;
  }
}

export declare module message {
  class Envelope {
    constructor();

    _message_enc: Uint8Array;
    mac: Uint8Array;
    message: message.Message;
    version: number;

    static decode(d: CBOR.Decoder): message.Envelope;
    static deserialise(buf: ArrayBuffer): message.Envelope;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(mac_key: derived.MacKey, message: message.Message): message.Envelope;
    serialise(): ArrayBuffer;
    verify(mac: derived.MacKey): boolean;
  }

  class Header {
    constructor();

    couter: number;
    prev_counter: number;
    ratchet_key: keys.PublicKey

    static decode(d: CBOR.Decoder): message.Header;
    static deserialise(buf: ArrayBuffer): message.Header;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(counter: number, prev_counter: number, ratchet_key: keys.PublicKey): message.Header;
    serialise(): ArrayBuffer;
  }

  class Message {
    constructor();

    static deserialise(buf: ArrayBuffer): message.Message;
    serialise(): ArrayBuffer;
  }

  class HeaderMessage {
    constructor();

    cipher_text: Uint8Array;
    header: Uint8Array;

    static decode(d: CBOR.Decoder): message.HeaderMessage;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(encrypted_header: Uint8Array, cipher_text: Uint8Array): message.HeaderMessage;
  }

  class PreKeyMessage {
    constructor();

    base_key: keys.PublicKey;
    identity_key: keys.IdentityKey;
    message: message.HeaderMessage;
    prekey_id: number;

    static decode(d: CBOR.Decoder): message.PreKeyMessage;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(prekey_id: number, base_key: keys.PublicKey, identity_key: keys.IdentityKey, message: message.HeaderMessage): message.PreKeyMessage;
  }
}

export declare module session {
  class ChainKey {
    constructor();

    idx: number;
    key: derived.MacKey;

    static decode(d: CBOR.Decoder): session.ChainKey;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static from_mac_key(key: derived.MacKey, counter: number): session.ChainKey;
    message_keys(): session.MessageKeys;
    next(): session.ChainKey;
  }

  class MessageKeys {
    constructor();

    cipher_key: derived.CipherKey;
    counter: number;
    mac_key: derived.MacKey;

    private _counter_as_nonce(): Uint8Array;
    static decode(d: CBOR.Decoder): session.MessageKeys;
    decrypt(ciphertext: Uint8Array): Uint8Array;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    encrypt(plaintext: string|Uint8Array): Uint8Array;
    static new(key: Uint8Array): derived.MacKey;
  }

  abstract class PreKeyStore {
    public prekeys: Array<keys.PreKey> | Array<number>;
    abstract get_prekey(prekey_id: number): Promise<keys.PreKey>;
    abstract remove(prekey_id: number): Promise<number>;
  }

  class RecvChain {
    constructor();

    static MAX_COUNTER_GAP: number;

    chain_key: session.ChainKey;
    ratchet_key: keys.PublicKey;
    head_key: derived.HeadKey;
    final_count: any;
    message_keys: Array<session.MessageKeys>;

    private static _try_head_key(start_index: number, end_index: number, encrypted_header: Uint8Array, head_key: derived.HeadKey): message.Header;
    commit_message_keys(keys: Array<session.MessageKeys>): void;
    static decode(d: CBOR.Decoder): session.RecvChain;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(chain_key: session.ChainKey, public_key: keys.PublicKey, head_key: derived.HeadKey): session.RecvChain;
    stage_message_keys(header: message.Header): Array<session.ChainKey|session.MessageKeys>;
    try_head_key(encrypted_header: Uint8Array): message.Header;
    try_message_keys(envelope: message.Envelope, header: message.Header, cipher_text: Uint8Array): Uint8Array;
    static try_next_head_key(encrypted_header: Uint8Array, next_head_key: derived.HeadKey): message.Header;
  }

  class RootKey {
    constructor();

    key: derived.CipherKey;

    static decode(d: CBOR.Decoder): session.RootKey;
    dh_ratchet(ours: keys.KeyPair, theirs: keys.PublicKey): Array<session.RootKey|session.ChainKey|derived.HeadKey>;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static from_cipher_key(cipher_key: derived.CipherKey): session.RootKey;
  }

  class SendChain {
    constructor();

    chain_key: session.ChainKey;
    ratchet_key: keys.KeyPair;
    head_key: derived.HeadKey;

    static decode(d: CBOR.Decoder): session.SendChain;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    static new(chain_key: session.ChainKey, keypair: keys.KeyPair, head_key: derived.HeadKey): session.SendChain;
  }

  interface SessionFromMessageTuple extends Array<session.Session | Uint8Array> { 0: session.Session; 1: Uint8Array; }

  interface PendingPreKeyTuple extends Array<number | keys.PublicKey> { 0: number; 1: keys.PublicKey; }

  class Session {
    constructor();

    static readonly MAX_RECV_CHAINS: number;
    static readonly MAX_SESSION_STATES: number;

    local_identity: any;
    pending_prekey: any;
    remote_identity: any;
    session_states: Array<session.SessionState>;
    version: number;

    private _decrypt_header_message(envelope: message.Envelope, msg: message.Message, state_index: number): Uint8Array;
    private _decrypt_prekey_message(envelope: message.Envelope, msg: message.Message, prekey_store: session.PreKeyStore): Promise<Uint8Array>;
    private _insert_session_state(state: session.SessionState): boolean;
    private _new_state(prekey_store: session.PreKeyStore, prekey_message: message.PreKeyMessage): Promise<session.SessionState>;
    private _try_decrypt_header_message(envelope: message.Envelope, message: message.Message, start: number): Promise<Uint8Array>
    static decode(local_identity: keys.IdentityKeyPair, d: CBOR.Decoder): session.Session;
    decrypt(prekey_store: session.PreKeyStore, envelope: message.Envelope): Promise<Uint8Array>;
    static deserialise(local_identity: keys.IdentityKeyPair, buf: ArrayBuffer): session.Session;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    encrypt(plaintext: string|Uint8Array): Promise<message.Envelope>;
    get_local_identity(): keys.PublicKey;
    static init_from_message(our_identity: keys.IdentityKeyPair, prekey_store: session.PreKeyStore, envelope: message.Envelope): Promise<SessionFromMessageTuple>;
    static init_from_prekey(local_identity: keys.IdentityKeyPair, remote_pkbundle: keys.PreKeyBundle): Promise<session.Session>;
    serialise(): ArrayBuffer;
  }

  class SessionState {
    constructor();

    next_recv_head_key: derived.HeadKey;
    next_send_head_key: derived.HeadKey;
    prev_counter: number;
    recv_chains: Array<session.RecvChain>;
    root_key: session.RootKey;
    send_chain: session.SendChain;

    static decode(d: CBOR.Decoder): session.SessionState;
    decrypt(envelope: message.Envelope, msg: message.HeaderMessage): Uint8Array;
    static deserialise(buf: ArrayBuffer): session.SessionState;
    encode(e: CBOR.Encoder): CBOR.Encoder;
    encrypt(identity_key: keys.IdentityKey, pending: PendingPreKeyTuple, plaintext: string|Uint8Array): message.Envelope;
    static init_as_alice(alice_identity_pair: keys.IdentityKeyPair, alice_base: keys.KeyPair, bob_pkbundle: keys.PreKeyBundle): session.SessionState;
    static init_as_bob(bob_ident: keys.IdentityKeyPair, bob_prekey: keys.KeyPair, alice_ident: keys.IdentityKey, alice_base: keys.PublicKey): session.SessionState;
    ratchet(ratchet_key: keys.KeyPair, prev_counter: number): void;
    serialise(): ArrayBuffer;
  }
}
