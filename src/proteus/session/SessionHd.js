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

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const MemoryUtil = require('../util/MemoryUtil');
const TypeUtil = require('../util/TypeUtil');

const DecodeError = require('../errors/DecodeError');
const DecryptError = require('../errors/DecryptError');
const ProteusError = require('../errors/ProteusError');

const IdentityKey = require('../keys/IdentityKey');
const IdentityKeyPair = require('../keys/IdentityKeyPair');
const KeyPair = require('../keys/KeyPair');
const PreKey = require('../keys/PreKey');
const PreKeyBundle = require('../keys/PreKeyBundle');
const PublicKey = require('../keys/PublicKey');

const HeaderMessage = require('../message/HeaderMessage');
const Envelope = require('../message/Envelope');
const PreKeyMessageHd = require('../message/PreKeyMessageHd');

const PreKeyStore = require('./PreKeyStore');

/** @module session */

/**
 * @class SessionHd
 * @throws {DontCallConstructor}
 */
class SessionHd {
  constructor() {
    this.local_identity = null;
    this.pending_prekey = null;
    this.remote_identity = null;
    this.session_states = [];
    this.version = 1;

    throw new DontCallConstructor(this);
  }

  /** @type {number} */
  static get MAX_RECV_CHAINS() {
    return 5;
  }

  /** @type {number} */
  static get MAX_SESSION_STATES() {
    return 100;
  }

  /**
   * @param {!keys.IdentityKeyPair} local_identity - Alice's Identity Key Pair
   * @param {!keys.PreKeyBundle} remote_pkbundle - Bob's Pre-Key Bundle
   * @returns {Promise<SessionHd>}
   */
  static init_from_prekey(local_identity, remote_pkbundle) {
    return new Promise((resolve) => {
      TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
      TypeUtil.assert_is_instance(PreKeyBundle, remote_pkbundle);

      const alice_base = KeyPair.new();

      const state = SessionStateHd.init_as_alice(local_identity, alice_base, remote_pkbundle);

      const session = ClassUtil.new_instance(this);
      session.local_identity = local_identity;
      session.remote_identity = remote_pkbundle.identity_key;
      session.pending_prekey = [remote_pkbundle.prekey_id, alice_base.public_key];
      session.session_states = [];

      session._insert_session_state(state);
      return resolve(session);
    });
  }

  /**
   * @param {!keys.IdentityKeyPair} our_identity
   * @param {!session.PreKeyStore} prekey_store
   * @param {!message.Envelope} envelope
   * @returns {Promise<Array<SessionHd|Uint8Array>>}
   * @throws {errors.DecryptError.InvalidMessage}
   * @throws {errors.DecryptError.PrekeyNotFound}
   */
  static init_from_message(our_identity, prekey_store, envelope) {
    return new Promise((resolve, reject) => {
      TypeUtil.assert_is_instance(IdentityKeyPair, our_identity);
      TypeUtil.assert_is_instance(PreKeyStore, prekey_store);
      TypeUtil.assert_is_instance(Envelope, envelope);

      const pkmsg = (() => {
        if (envelope.message instanceof HeaderMessage) {
          throw new DecryptError.InvalidMessage(
            'Can\'t initialise a session from a HeaderMessage.', DecryptError.CODE.CASE_201
          );
        } else if (envelope.message instanceof PreKeyMessageHd) {
          return envelope.message;
        } else {
          throw new DecryptError.InvalidMessage(
            'Unknown message format: The message is neither a "HeaderMessage" nor a "PreKeyMessageHd".', DecryptError.CODE.CASE_202
          );
        }
      })();

      const session = ClassUtil.new_instance(SessionHd);
      session.local_identity = our_identity;
      session.remote_identity = pkmsg.identity_key;
      session.pending_prekey = null;
      session.session_states = [];

      return session._new_state(prekey_store, pkmsg).then((state) => {
        const plain = state.decrypt(envelope, pkmsg.message);
        session._insert_session_state(state);

        if (pkmsg.prekey_id < PreKey.MAX_PREKEY_ID) {
          MemoryUtil.zeroize(prekey_store.prekeys[pkmsg.prekey_id]);
          return prekey_store.remove(pkmsg.prekey_id).then(() => resolve([session, plain])).catch((error) => {
            reject(new DecryptError.PrekeyNotFound(`Could not delete PreKey: ${error.message}`, DecryptError.CODE.CASE_203));
          });
        } else {
          return resolve([session, plain]);
        }
      }).catch(reject);
    });
  }

  /**
   * @param {!session.PreKeyStore} pre_key_store
   * @param {!message.PreKeyMessageHd} pre_key_message
   * @returns {Promise<session.SessionStateHd>}
   * @private
   * @throws {errors.ProteusError}
   */
  _new_state(pre_key_store, pre_key_message) {
    return pre_key_store.get_prekey(pre_key_message.prekey_id).then((pre_key) => {
      if (pre_key) {
        return SessionStateHd.init_as_bob(
          this.local_identity,
          pre_key.key_pair,
          pre_key_message.identity_key,
          pre_key_message.base_key
        );
      }
      throw new ProteusError('Unable to get PreKey from PreKey store.', ProteusError.prototype.CODE.CASE_101);
    });
  }

  /**
   * @param {!session.SessionStateHd} state
   * @returns {boolean}
   * @private
   */
  _insert_session_state(state) {
    this.session_states.unshift(state);

    const size = this.session_states.length;
    if (size < SessionHd.MAX_SESSION_STATES) {
      return true;
    }

    // if we get here, it means that we have more than MAX_SESSION_STATES and
    // we need to evict the oldest one.
    return delete this.session_states[size - 1];
  }

  /** @returns {keys.PublicKey} */
  get_local_identity() {
    return this.local_identity.public_key;
  }

  /**
   * @param {!(string|Uint8Array)} plaintext - The plaintext which needs to be encrypted
   * @return {Promise<message.Envelope>} Encrypted message
   */
  encrypt(plaintext) {
    return new Promise((resolve, reject) => {
      const state = this.session_states[0];

      if (!state) {
        return reject(new ProteusError(
          'Could not find session.', ProteusError.prototype.CODE.CASE_102
        ));
      }

      return resolve(state.encrypt(
        this.local_identity.public_key,
        this.pending_prekey,
        plaintext
      ));
    });
  }

  /**
   * @param {!session.PreKeyStore} prekey_store
   * @param {!message.Envelope} envelope
   * @returns {Promise<Uint8Array>}
   * @throws {errors.DecryptError}
   */
  decrypt(prekey_store, envelope) {
    return new Promise((resolve) => {
      TypeUtil.assert_is_instance(PreKeyStore, prekey_store);
      TypeUtil.assert_is_instance(Envelope, envelope);

      const msg = envelope.message;
      if (msg instanceof HeaderMessage) {
        return resolve(this._try_decrypt_header_message(envelope, msg, 0));
      } else if (msg instanceof PreKeyMessageHd) {
        const actual_fingerprint = msg.identity_key.fingerprint();
        const expected_fingerprint = this.remote_identity.fingerprint();
        if (actual_fingerprint !== expected_fingerprint) {
          const message = `Fingerprints do not match: We expected '${expected_fingerprint}', but received '${actual_fingerprint}'.`;
          throw new DecryptError.RemoteIdentityChanged(message, DecryptError.CODE.CASE_204);
        }
        return resolve(this._decrypt_prekey_message(envelope, msg, prekey_store));
      } else {
        throw new DecryptError('Unknown message type.', DecryptError.CODE.CASE_200);
      }
    });
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.Message} msg
   * @param {!session.PreKeyStore} prekey_store
   * @private
   * @returns {Promise<Uint8Array>}
   * @throws {errors.DecryptError}
   */
  _decrypt_prekey_message(envelope, msg, prekey_store) {
    return Promise.resolve().then(() => this._decrypt_header_message(envelope, msg.message)).catch((error) => {
      const try_create_new_state_and_decrypt = () => {
        return this._new_state(prekey_store, msg).then((state) => {
          const plaintext = state.decrypt(envelope, msg.message);
          if (msg.prekey_id !== PreKey.MAX_PREKEY_ID) {
            MemoryUtil.zeroize(prekey_store.prekeys[msg.prekey_id]);
            prekey_store.remove(msg.prekey_id);
          }

          this._insert_session_state(state);
          this.pending_prekey = null;

          return plaintext;
        });
      };

      if (error instanceof DecryptError.InvalidMessage) {
        // session state not exist
        try_create_new_state_and_decrypt();
      }

      if (error instanceof DecryptError.HeaderDecryptionFailed) {
        // we had tried it once already
        let fail_counter = 1;
        const state_size = this.session_states.length;
        if (state_size === fail_counter) {
          return try_create_new_state_and_decrypt();
        }
        // start from index 1
        return this._try_decrypt_header_message(envelope, msg.message, 1)
          .catch((err) => {
            if (err instanceof DecryptError.HeaderDecryptionFailed) {
              return try_create_new_state_and_decrypt();
            } else {
              throw err;
            }
          });
      }

      throw error;
    });
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.Message} message
   * @param {!number} start
   * @private
   * @returns {Promise<Uint8Array>}
   */
  _try_decrypt_header_message(envelope, message, start) {
    return new Promise((resolve, reject) => {
      let fail_counter = start;
      const state_size = this.session_states.length;
      const HeaderDecryptionFailed = DecryptError.HeaderDecryptionFailed;

      const try_decrypt_header_message = () => this._decrypt_header_message(envelope, message, fail_counter);
      const handle_error = (err) => {
        if (err instanceof HeaderDecryptionFailed) {
          fail_counter++;
          if (fail_counter === state_size) {
            reject(new HeaderDecryptionFailed('All states failed', DecryptError.CODE.CASE_216));
          }
          Promise.resolve()
            .then(try_decrypt_header_message)
            .then(resolve)
            .catch(handle_error);
        } else {
          // if we get here, it means that we had decrypted header, but something else has gone wrong
          reject(err);
        }
      };

      Promise.resolve()
        .then(try_decrypt_header_message)
        .then(resolve)
        .catch(handle_error);
    });
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.Message} msg
   * @param {number} state_index
   * @private
   * @returns {Uint8Array}
   */
  _decrypt_header_message(envelope, msg, state_index = 0) {
    let state = this.session_states[state_index];
    if (!state) {
      throw new DecryptError.InvalidMessage('Local session not found.', DecryptError.CODE.CASE_205);
    }

    // serialise and de-serialise for a deep clone
    // THIS IS IMPORTANT, DO NOT MUTATE THE SESSION STATE IN-PLACE
    // mutating in-place can lead to undefined behavior and undefined state in edge cases
    state = SessionStateHd.deserialise(state.serialise());

    const plaintext = state.decrypt(envelope, msg);

    this.pending_prekey = null;

    // Avoid `unshift` operation when possible
    if (state_index === 0) {
      this.session_states[0] = state;
    } else {
      this.session_states.splice(state_index, 1);
      this._insert_session_state(state);
    }

    return plaintext;
  }

  /**
   * @returns {ArrayBuffer}
   */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param {!keys.IdentityKeyPair} local_identity
   * @param {!ArrayBuffer} buf
   * @returns {SessionHd}
   */
  static deserialise(local_identity, buf) {
    TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
    TypeUtil.assert_is_instance(ArrayBuffer, buf);

    const d = new CBOR.Decoder(buf);
    return this.decode(local_identity, d);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {void}
   */
  encode(e) {
    e.object(5);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    this.local_identity.public_key.encode(e);
    e.u8(2);
    this.remote_identity.encode(e);

    e.u8(3);
    if (this.pending_prekey) {
      e.object(2);
      e.u8(0);
      e.u16(this.pending_prekey[0]);
      e.u8(1);
      this.pending_prekey[1].encode(e);
    } else {
      e.null();
    }

    e.u8(4);
    e.array(this.session_states.length);
    this.session_states.map((session_state) => session_state.encode(e));
  }

  /**
   * @param {!keys.IdentityKeyPair} local_identity
   * @param {!CBOR.Decoder} d
   * @returns {SessionHd}
   */
  static decode(local_identity, d) {
    TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(this);

    const nprops = d.object();
    for (let n = 0; n <= nprops - 1; n++) {
      switch (d.u8()) {
        case 0: {
          self.version = d.u8();
          break;
        }
        case 1: {
          const ik = IdentityKey.decode(d);
          if (local_identity.public_key.fingerprint() !== ik.fingerprint()) {
            throw new DecodeError.LocalIdentityChanged(null, DecodeError.CODE.CASE_300);
          }
          self.local_identity = local_identity;
          break;
        }
        case 2: {
          self.remote_identity = IdentityKey.decode(d);
          break;
        }
        case 3: {
          switch (d.optional(() => d.object())) {
            case null:
              self.pending_prekey = null;
              break;
            case 2:
              self.pending_prekey = [null, null];
              for (let k = 0; k <= 1; ++k) {
                switch (d.u8()) {
                  case 0:
                    self.pending_prekey[0] = d.u16();
                    break;
                  case 1:
                    self.pending_prekey[1] = PublicKey.decode(d);
                }
              }
              break;
            default:
              throw new DecodeError.InvalidType(null, DecodeError.CODE.CASE_301);
          }
          break;
        }
        case 4: {
          self.session_states = [];
          let len = d.array();
          while (len--) {
            self.session_states.push(SessionStateHd.decode(d));
          }
          break;
        }
        default: {
          d.skip();
        }
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_instance(IdentityKeyPair, self.local_identity);
    TypeUtil.assert_is_instance(IdentityKey, self.remote_identity);
    TypeUtil.assert_is_instance(Array, self.session_states);

    return self;
  }
}

module.exports = SessionHd;

const SessionStateHd = require('./SessionStateHd');
