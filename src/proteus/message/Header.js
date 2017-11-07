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

/** @module message */

/**
 * @class Header
 * @throws {DontCallConstructor}
 */
class Header {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {!number} counter
   * @param {!number} prev_counter
   * @param {!keys.PublicKey} ratchet_key
   * @returns {Header} - `this`
   */
  static new(counter, prev_counter, ratchet_key) {
    TypeUtil.assert_is_integer(counter);
    TypeUtil.assert_is_integer(prev_counter);
    TypeUtil.assert_is_instance(PublicKey, ratchet_key);

    const hd = ClassUtil.new_instance(Header);

    hd.counter = counter;
    hd.prev_counter = prev_counter;
    hd.ratchet_key = ratchet_key;

    Object.freeze(hd);
    return hd;
  }

  /** @returns {ArrayBuffer} - The serialized header */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param {!ArrayBuffer} buf
   * @returns {Header}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);

    const d = new CBOR.Decoder(buf);
    return Header.decode(d);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    e.u32(this.counter);
    e.u8(1);
    e.u32(this.prev_counter);
    e.u8(2);
    return this.ratchet_key.encode(e);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {Header}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let counter = null;
    let prev_counter = null;
    let ratchet_key = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          counter = d.u32();
          break;
        case 1:
          prev_counter = d.u32();
          break;
        case 2:
          ratchet_key = PublicKey.decode(d);
          break;

        default:
          d.skip();
      }
    }

    return Header.new(counter, prev_counter, ratchet_key);
  }
}

module.exports = Header;
