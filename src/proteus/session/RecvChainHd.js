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
const TypeUtil = require('../util/TypeUtil');

const PublicKey = require('../keys/PublicKey');

const DecryptError = require('../errors/DecryptError');
const ProteusError = require('../errors/ProteusError');

const Header = require('../message/Header');
const Envelope = require('../message/Envelope');

const ChainKey = require('./ChainKey');
const HeadKey = require('../derived/HeadKey');
const MessageKeys = require('./MessageKeys');

/** @module session */

/**
 * @class RecvChainHd
 * @throws {DontCallConstructor}
 */
class RecvChainHd {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {!session.ChainKey} chain_key
   * @param {!keys.PublicKey} public_key
   * @param {!derived.HeadKey} head_key
   * @returns {session.RecvChainHd}
   */
  static new(chain_key, public_key, head_key) {
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(PublicKey, public_key);

    const rc = ClassUtil.new_instance(RecvChainHd);
    rc.chain_key = chain_key;
    rc.ratchet_key = public_key;
    rc.head_key = head_key;
    rc.final_count = null;
    rc.message_keys = [];
    return rc;
  }

  /**
   * @param {!number} start_index
   * @param {!number} end_index
   * @param {!Uint8Array} encrypted_header - encrypted header
   * @param {!derived.HeadKey} head_key
   * @returns {message.Header}
   * @private
   */
  static _try_head_key(start_index, end_index, encrypted_header, head_key) {
    const [header, index] = (() => {
      for (let i = start_index; i <= end_index; i++) {
        try {
          const header_typed_array = head_key.decrypt(encrypted_header, HeadKey.index_as_nonce(i));
          return [Header.deserialise(header_typed_array.buffer), i];
        } catch (err) {
          // noop
        }
      }
      return [null, 0];
    })();

    if (!header) {
      throw new DecryptError.HeaderDecryptionFailed('Head key not match', DecryptError.CODE.CASE_213);
    }

    if (header.counter !== index) {
      throw new DecryptError.InvalidHeader('Invalid header', DecryptError.CODE.CASE_214);
    }

    return header;
  }

  /**
   * @param {!Uint8Array} encrypted_header - encrypted header
   * @param {!derived.HeadKey} next_head_key
   * @returns {message.Header}
   */
  static try_next_head_key(encrypted_header, next_head_key) {

    return RecvChainHd._try_head_key(0, RecvChainHd.MAX_COUNTER_GAP, encrypted_header, next_head_key);
  }

  /**
   * @param {!Uint8Array} encrypted_header - encrypted header
   * @returns {message.Header}
   */
  try_head_key(encrypted_header) {
    const final_count = this.final_count;

    const start_index = this.message_keys.length > 0
      ? this.message_keys[0].counter
      : this.chain_key.idx;
    const end_index = final_count !== null
      ? final_count - 1
      : start_index + RecvChainHd.MAX_COUNTER_GAP;

    return RecvChainHd._try_head_key(start_index, end_index, encrypted_header, this.head_key);
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.Header} header
   * @param {!Uint8Array} cipher_text
   * @returns {Uint8Array}
   */
  try_message_keys(envelope, header, cipher_text) {
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(Header, header);
    TypeUtil.assert_is_instance(Uint8Array, cipher_text);

    if (this.message_keys[0] && this.message_keys[0].counter > header.counter) {
      const message = `Message too old. Counter for oldest staged chain key is '${this.message_keys[0].counter}' while message counter is '${header.counter}'.`;
      throw new DecryptError.OutdatedMessage(message, DecryptError.CODE.CASE_208);
    }

    const idx = this.message_keys.findIndex((mk) => {
      return mk.counter === header.counter;
    });

    if (idx === -1) {
      throw new DecryptError.DuplicateMessage(null, DecryptError.CODE.CASE_209);
    }

    const mk = this.message_keys.splice(idx, 1)[0];
    if (!envelope.verify(mk.mac_key)) {
      const message = `Envelope verification failed for message with counter behind. Message index is '${header.counter}' while receive chain index is '${this.chain_key.idx}'.`;
      throw new DecryptError.InvalidSignature(message, DecryptError.CODE.CASE_210);
    }

    return mk.decrypt(cipher_text);
  }

  /**
   * @param {!message.Header} header
   * @returns {Array<session.ChainKey>|session.MessageKeys}
   */
  stage_message_keys(header) {
    TypeUtil.assert_is_instance(Header, header);

    const num = header.counter - this.chain_key.idx;
    if (num > RecvChainHd.MAX_COUNTER_GAP) {
      if (this.chain_key.idx === 0) {
        throw new DecryptError.TooDistantFuture('Skipped too many message at the beginning of a receive chain.', DecryptError.CODE.CASE_211);
      }
      throw new DecryptError.TooDistantFuture(`Skipped too many message within a used receive chain. Receive chain counter is '${this.chain_key.idx}'`, DecryptError.CODE.CASE_212);
    }

    let keys = [];
    let chk = this.chain_key;

    for (let i = 0; i <= num - 1; i++) {
      keys.push(chk.message_keys());
      chk = chk.next();
    }

    const mk = chk.message_keys();
    return [chk, mk, keys];
  }

  /**
   * @param {!Array<session.MessageKeys>} keys
   * @returns {void}
   */
  commit_message_keys(keys) {
    TypeUtil.assert_is_instance(Array, keys);
    keys.map((k) => TypeUtil.assert_is_instance(MessageKeys, k));

    if (keys.length > RecvChainHd.MAX_COUNTER_GAP) {
      throw new ProteusError(`Number of message keys (${keys.length}) exceed message chain counter gap (${RecvChainHd.MAX_COUNTER_GAP}).`, ProteusError.prototype.CODE.CASE_103);
    }

    const excess = this.message_keys.length + keys.length - RecvChainHd.MAX_COUNTER_GAP;

    for (let i = 0; i <= excess - 1; i++) {
      this.message_keys.shift();
    }

    keys.map((k) => this.message_keys.push(k));

    if (keys.length > RecvChainHd.MAX_COUNTER_GAP) {
      throw new ProteusError(`Skipped message keys which exceed the message chain counter gap (${RecvChainHd.MAX_COUNTER_GAP}).`, ProteusError.prototype.CODE.CASE_104);
    }
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {Array<CBOR.Encoder>}
   */
  encode(e) {
    e.object(5);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    this.ratchet_key.encode(e);
    e.u8(2);
    this.head_key.encode(e);
    e.u8(3);
    if (this.final_count !== null) {
      e.u32(this.final_count);
    } else {
      e.null();
    }

    e.u8(4);
    e.array(this.message_keys.length);
    return this.message_keys.map((k) => k.encode(e));
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {RecvChainHd}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(RecvChainHd);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0: {
          self.chain_key = ChainKey.decode(d);
          break;
        }
        case 1: {
          self.ratchet_key = PublicKey.decode(d);
          break;
        }
        case 2: {
          self.head_key = HeadKey.decode(d);
          break;
        }
        case 3: {
          self.final_count = d.optional(() => d.u32());
          break;
        }
        case 4: {
          self.message_keys = [];

          let len = d.array();
          while (len--) {
            self.message_keys.push(MessageKeys.decode(d));
          }
          break;
        }
        default: {
          d.skip();
        }
      }
    }

    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(PublicKey, self.ratchet_key);
    TypeUtil.assert_is_instance(HeadKey, self.head_key);
    TypeUtil.assert_is_instance(Array, self.message_keys);

    return self;
  }
}

/** @type {number} */
RecvChainHd.MAX_COUNTER_GAP = 1000;

module.exports = RecvChainHd;
