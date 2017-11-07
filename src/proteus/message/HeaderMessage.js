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

const Message = require('./Message');

/** @module message */

/**
 * @extends Message
 * @throws {DontCallConstructor}
 */
class HeaderMessage extends Message {
  constructor() {
    super();
    throw new DontCallConstructor(this);
  }

  /**
   * @param {!Uint8Array} encrypted_header - encrypted header
   * @param {!Uint8Array} cipher_text
   * @returns {HeaderMessage} - `this`
   */
  static new(encrypted_header, cipher_text) {
    TypeUtil.assert_is_instance(Uint8Array, encrypted_header);
    TypeUtil.assert_is_instance(Uint8Array, cipher_text);

    const hm = ClassUtil.new_instance(HeaderMessage);

    hm.header = encrypted_header;
    hm.cipher_text = cipher_text;

    Object.freeze(hm);
    return hm;
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(2);

    e.u8(0);
    e.object(1);
    e.u8(0);
    e.bytes(this.header);

    e.u8(1);
    return e.bytes(this.cipher_text);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {HeaderMessage}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let header = null;
    let cipher_text = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0: {
          const nprops_mac = d.object();
          for (let j = 0; j <= nprops_mac - 1; j++) {
            switch (d.u8()) {
              case 0:
                header = new Uint8Array(d.bytes());
                break;
              default:
                d.skip();
            }
          }
          break;
        }
        case 1: {
          cipher_text = new Uint8Array(d.bytes());
          break;
        }
        default: {
          d.skip();
        }
      }
    }

    return HeaderMessage.new(header, cipher_text);
  }
}

module.exports = HeaderMessage;
