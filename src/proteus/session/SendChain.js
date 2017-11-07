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

const ChainKey = require('./ChainKey');
const HeadKey = require('../derived/HeadKey');
const KeyPair = require('../keys/KeyPair');

/** @module session */

/**
 * @class SendChain
 * @throws {DontCallConstructor}
 *
 * extends `SendChain` for `SessionState`'s encode/decode compatibility
 */
class SendChain {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {!session.ChainKey} chain_key
   * @param {!keys.KeyPair} keypair
   * @param {!derived.HeadKey} head_key
   * @returns {session.SendChain}
   */
  static new(chain_key, keypair, head_key) {
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(KeyPair, keypair);
    TypeUtil.assert_is_instance(HeadKey, head_key);

    const sc = ClassUtil.new_instance(SendChain);
    sc.chain_key = chain_key;
    sc.ratchet_key = keypair;
    sc.head_key = head_key;
    return sc;
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    this.ratchet_key.encode(e);
    e.u8(2);
    return this.head_key.encode(e);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {SendChain}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    const self = ClassUtil.new_instance(SendChain);
    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.chain_key = ChainKey.decode(d);
          break;
        case 1:
          self.ratchet_key = KeyPair.decode(d);
          break;
        case 2:
          self.head_key = HeadKey.decode(d);
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(KeyPair, self.ratchet_key);
    TypeUtil.assert_is_instance(HeadKey, self.head_key);
    return self;
  }
}

module.exports = SendChain;
