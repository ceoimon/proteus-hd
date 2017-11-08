/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const CBOR = require('wire-webapp-cbor');

const ArrayUtil = require('../util/ArrayUtil');
const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const MemoryUtil = require('../util/MemoryUtil');
const TypeUtil = require('../util/TypeUtil');

const DecryptError = require('../errors/DecryptError');

const DerivedSecrets = require('../derived/DerivedSecrets');
const HeadKey = require('../derived/HeadKey');

const IdentityKey = require('../keys/IdentityKey');
const IdentityKeyPair = require('../keys/IdentityKeyPair');
const KeyPair = require('../keys/KeyPair');
const PreKeyBundle = require('../keys/PreKeyBundle');
const PublicKey = require('../keys/PublicKey');

const Header = require('../message/Header');
const HeaderMessage = require('../message/HeaderMessage');
const Envelope = require('../message/Envelope');
const PreKeyMessage = require('../message/PreKeyMessage');

const ChainKey = require('./ChainKey');
const RecvChain = require('./RecvChain');
const RootKey = require('./RootKey');
const SendChain = require('./SendChain');
const Session = require('./Session');

/** @module session */

/** @class SessionState */
class SessionState {
  constructor() {
    this.recv_chains = [];
    this.send_chain = null;
    this.root_key = null;
    this.prev_counter = null;
    this.next_send_head_key = null;
    this.next_recv_head_key = null;

    throw new DontCallConstructor(this);
  }

  /**
   * @param {!keys.IdentityKeyPair} alice_identity_pair
   * @param {!keys.PublicKey} alice_base
   * @param {!keys.PreKeyBundle} bob_pkbundle
   * @returns {SessionState}
   */
  static init_as_alice(alice_identity_pair, alice_base, bob_pkbundle) {
    TypeUtil.assert_is_instance(IdentityKeyPair, alice_identity_pair);
    TypeUtil.assert_is_instance(KeyPair, alice_base);
    TypeUtil.assert_is_instance(PreKeyBundle, bob_pkbundle);

    const master_key = ArrayUtil.concatenate_array_buffers([
      alice_identity_pair.secret_key.shared_secret(bob_pkbundle.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.identity_key.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.public_key),
    ]);

    const derived_secrets = DerivedSecrets.kdf_without_salt(master_key, 'handshake');
    MemoryUtil.zeroize(master_key);

    const rootkey = RootKey.from_cipher_key(derived_secrets.cipher_key);
    const chainkey = ChainKey.from_mac_key(derived_secrets.mac_key, 0);
    const head_key_alice = derived_secrets.head_key_alice;
    const next_head_key_Bob = derived_secrets.next_head_key_bob;

    const send_ratchet = KeyPair.new();
    const [rok, chk, nextHeadKey] = rootkey.dh_ratchet(send_ratchet, bob_pkbundle.public_key);
    const recv_chains = [RecvChain.new(chainkey, bob_pkbundle.public_key, next_head_key_Bob)];
    const send_chain = SendChain.new(chk, send_ratchet, head_key_alice);

    const state = ClassUtil.new_instance(SessionState);
    state.next_send_head_key = nextHeadKey;
    state.recv_chains = recv_chains;
    state.next_recv_head_key = next_head_key_Bob;
    state.send_chain = send_chain;
    state.root_key = rok;
    state.prev_counter = 0;
    return state;
  }

  /**
   * @param {!keys.IdentityKeyPair} bob_ident
   * @param {!keys.KeyPair} bob_prekey
   * @param {!keys.IdentityKey} alice_ident
   * @param {!keys.PublicKey} alice_base
   * @returns {SessionState}
   */
  static init_as_bob(bob_ident, bob_prekey, alice_ident, alice_base) {
    TypeUtil.assert_is_instance(IdentityKeyPair, bob_ident);
    TypeUtil.assert_is_instance(KeyPair, bob_prekey);
    TypeUtil.assert_is_instance(IdentityKey, alice_ident);
    TypeUtil.assert_is_instance(PublicKey, alice_base);

    const master_key = ArrayUtil.concatenate_array_buffers([
      bob_prekey.secret_key.shared_secret(alice_ident.public_key),
      bob_ident.secret_key.shared_secret(alice_base),
      bob_prekey.secret_key.shared_secret(alice_base),
    ]);

    const derived_secrets = DerivedSecrets.kdf_without_salt(master_key, 'handshake');
    MemoryUtil.zeroize(master_key);

    const rootkey = RootKey.from_cipher_key(derived_secrets.cipher_key);
    const chainkey = ChainKey.from_mac_key(derived_secrets.mac_key, 0);
    const head_key_alice = derived_secrets.head_key_alice;
    const next_head_key_bob = derived_secrets.next_head_key_bob;
    const send_chain = SendChain.new(chainkey, bob_prekey, next_head_key_bob);

    const state = ClassUtil.new_instance(SessionState);
    state.next_send_head_key = next_head_key_bob;
    state.next_recv_head_key = head_key_alice;
    state.send_chain = send_chain;
    state.root_key = rootkey;
    state.prev_counter = 0;
    return state;
  }

  /**
   * @param {!keys.KeyPair} ratchet_key
   * @param {!number} prev_counter
   * @returns {void}
   */
  ratchet(ratchet_key, prev_counter) {
    const new_ratchet = KeyPair.new();

    const [recv_root_key, recv_chain_key, next_recv_head_key] =
      this.root_key.dh_ratchet(this.send_chain.ratchet_key, ratchet_key);

    const [send_root_key, send_chain_key, next_send_head_key] =
      recv_root_key.dh_ratchet(new_ratchet, ratchet_key);

    const recv_chain = RecvChain.new(recv_chain_key, ratchet_key, this.next_recv_head_key);
    const send_chain = SendChain.new(send_chain_key, new_ratchet, this.next_send_head_key);

    this.root_key = send_root_key;
    this.prev_counter = this.send_chain.chain_key.idx;
    this.send_chain = send_chain;
    this.next_send_head_key = next_send_head_key;
    this.next_recv_head_key = next_recv_head_key;

    // save last chains counter
    const last_chain = this.recv_chains[0];
    if (last_chain) {
      last_chain.final_count = prev_counter;
    }
    this.recv_chains.unshift(recv_chain);

    if (this.recv_chains.length > Session.MAX_RECV_CHAINS) {
      for (let index = Session.MAX_RECV_CHAINS; index < this.recv_chains.length; index++) {
        MemoryUtil.zeroize(this.recv_chains[index]);
      }

      this.recv_chains = this.recv_chains.slice(0, Session.MAX_RECV_CHAINS);
    }
  }

  /**
   * @param {!keys.IdentityKey} identity_key - Public identity key of the local identity key pair
   * @param {!Array<number|keys.PublicKey>} pending - Pending pre-key
   * @param {!(string|Uint8Array)} plaintext - The plaintext to encrypt
   * @param {number} confuse_pre_key_id - Use to create confused pre-key message
   * @returns {message.Envelope}
   */
  encrypt(identity_key, pending, plaintext, confuse_pre_key_id) {
    if (pending) {
      TypeUtil.assert_is_integer(pending[0]);
      TypeUtil.assert_is_instance(PublicKey, pending[1]);
    }
    TypeUtil.assert_is_instance(IdentityKey, identity_key);

    const message_index = this.send_chain.chain_key.idx;
    const msgkeys = this.send_chain.chain_key.message_keys();
    const head_key = this.send_chain.head_key;

    const header = Header.new(
      message_index,
      this.prev_counter,
      this.send_chain.ratchet_key.public_key
    ).serialise();

    let message = HeaderMessage.new(
      head_key.encrypt(header, HeadKey.index_as_nonce(message_index)),
      msgkeys.encrypt(plaintext)
    );

    if (pending) {
      message = PreKeyMessage.new(pending[0], pending[1], identity_key, message);
    }

    // create a confused pre-key message
    if (confuse_pre_key_id !== undefined) {
      message = PreKeyMessage.new(confuse_pre_key_id, KeyPair.new().public_key, identity_key, message);
    }

    const env = Envelope.new(msgkeys.mac_key, message);
    this.send_chain.chain_key = this.send_chain.chain_key.next();
    return env;
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.HeaderMessage} msg
   * @returns {Uint8Array}
   */
  decrypt(envelope, msg) {
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(HeaderMessage, msg);

    const encrypted_header = msg.header;

    const [header, recv_chain] = (() => {
      // Try next_head_key first, run a DH-ratchet step and create a new receiving chain if it succeeded.
      try {
        return [RecvChain.try_next_head_key(encrypted_header, this.next_recv_head_key), null];
      } catch (err) {
        handleHeaderDecryptionError(err);
      }

      // Otherwise, try old receving chains.
      const recv_chains_length = this.recv_chains.length;
      let idx = 0;
      for (; idx < recv_chains_length; idx++) {
        const _recv_chain = this.recv_chains[idx];
        try {
          return [_recv_chain.try_head_key(encrypted_header), _recv_chain];
        } catch (err) {
          handleHeaderDecryptionError(err);
        }
      }

      return [null, null];

      function handleHeaderDecryptionError(err) {
        if (!(err instanceof DecryptError.HeaderDecryptionFailed)) {
          throw err;
        }
      }
    })();

    if (!header) {
      throw new DecryptError.HeaderDecryptionFailed('All chains failed', DecryptError.CODE.CASE_215);
    }

    const rc = (() => {
      if (!recv_chain) {
        this.ratchet(header.ratchet_key, header.prev_counter);
        return this.recv_chains[0];
      }
      return recv_chain;
    })();

    const cipher_text = msg.cipher_text;
    const counter = header.counter;
    const recv_chain_index = rc.chain_key.idx;
    if (counter < recv_chain_index) {
      return rc.try_message_keys(envelope, header, cipher_text);
    } else if (counter == recv_chain_index) {
      const mks = rc.chain_key.message_keys();

      if (!envelope.verify(mks.mac_key)) {
        throw new DecryptError.InvalidSignature(`Envelope verification failed for message with counters in sync at '${counter}'`, DecryptError.CODE.CASE_206);
      }

      const plain = mks.decrypt(cipher_text);
      rc.chain_key = rc.chain_key.next();
      return plain;

    } else if (counter > recv_chain_index) {
      const [chk, mk, mks] = rc.stage_message_keys(header);

      if (!envelope.verify(mk.mac_key)) {
        throw new DecryptError.InvalidSignature(`Envelope verification failed for message with counter ahead. Message index is '${counter}' while receive chain index is '${recv_chain_index}'.`, DecryptError.CODE.CASE_207);
      }

      const plain = mk.decrypt(cipher_text);

      rc.chain_key = chk.next();
      rc.commit_message_keys(mks);

      return plain;
    }
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return SessionState.decode(new CBOR.Decoder(buf));
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(6);
    e.u8(0);
    this.next_send_head_key.encode(e);
    e.u8(1);
    this.next_recv_head_key.encode(e);
    e.u8(2);
    e.array(this.recv_chains.length);
    this.recv_chains.map((rch) => rch.encode(e));
    e.u8(3);
    this.send_chain.encode(e);
    e.u8(4);
    this.root_key.encode(e);
    e.u8(5);
    return e.u32(this.prev_counter);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {SessionState}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(SessionState);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0: {
          self.next_send_head_key = HeadKey.decode(d);
          break;
        }
        case 1: {
          self.next_recv_head_key = HeadKey.decode(d);
          break;
        }
        case 2: {
          self.recv_chains = [];
          let len = d.array();
          while (len--) {
            self.recv_chains.push(RecvChain.decode(d));
          }
          break;
        }
        case 3: {
          self.send_chain = SendChain.decode(d);
          break;
        }
        case 4: {
          self.root_key = RootKey.decode(d);
          break;
        }
        case 5: {
          self.prev_counter = d.u32();
          break;
        }
        default: {
          d.skip();
        }
      }
    }

    TypeUtil.assert_is_instance(HeadKey, self.next_send_head_key);
    TypeUtil.assert_is_instance(HeadKey, self.next_recv_head_key);
    TypeUtil.assert_is_instance(SendChain, self.send_chain);
    TypeUtil.assert_is_instance(Array, self.recv_chains);
    TypeUtil.assert_is_instance(RootKey, self.root_key);
    TypeUtil.assert_is_integer(self.prev_counter);

    return self;
  }
}

module.exports = SessionState;
