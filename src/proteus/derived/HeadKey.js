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
const sodium = require('libsodium-wrappers-sumo');

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const TypeUtil = require('../util/TypeUtil');

/** @module derived */

/**
 * @class HeadKey
 * @throws {DontCallConstructor}
 */
class HeadKey {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {!Uint8Array} key
   * @returns {HeadKey} - `this`
   */
  static new(key) {
    TypeUtil.assert_is_instance(Uint8Array, key);

    const hk = ClassUtil.new_instance(HeadKey);
    /** @type {Uint8Array} */
    hk.key = key;
    return hk;
  }

  /**
   * @param {!number} idx
   * @returns {Uint8Array}
   */
  static index_as_nonce(idx) {
    const nonce = new ArrayBuffer(8);
    new DataView(nonce).setUint32(0, idx);
    return new Uint8Array(nonce);
  }

  /**
   * @param {!ArrayBuffer} header - The serialized header to encrypt
   * @param {!Uint8Array} nonce
   * @returns {Uint8Array} - Encrypted payload
   */
  encrypt(header, nonce) {
    header = new Uint8Array(header);

    return sodium.crypto_stream_chacha20_xor(header, nonce, this.key, 'uint8array');
  }

  /**
   * @param {!Uint8Array} encrypted_header
   * @param {!Uint8Array} nonce
   * @returns {Uint8Array}
   */
  decrypt(encrypted_header, nonce) {
    return this.encrypt(encrypted_header, nonce);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.key);
  }

  /**
   * @param {!CBOR.Encoder} d
   * @returns {HeadKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let key_bytes = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          key_bytes = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    return HeadKey.new(key_bytes);
  }
}

module.exports = HeadKey;
