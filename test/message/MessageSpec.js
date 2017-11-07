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

describe('Message', () => {
  const fake_pubkey = (byte) => {
    const pub_edward = new Uint8Array(32);
    pub_edward.fill(byte);
    const pub_curve = sodium.crypto_sign_ed25519_pk_to_curve25519(pub_edward);

    return Proteus.keys.PublicKey.new(pub_edward, pub_curve);
  };

  const bk = fake_pubkey(0xFF);
  const ik = Proteus.keys.IdentityKey.new(fake_pubkey(0xA0));

  it('should serialise and deserialise a HeaderMessage correctly', () => {
    const expected = '01a200a1004501020304050145060708090a';

    const hd = new Uint8Array([1, 2, 3, 4, 5]);
    const msg = Proteus.message.HeaderMessage.new(
      hd,
      new Uint8Array([6, 7, 8, 9, 10])
    );

    const bytes = new Uint8Array(msg.serialise());
    assert(expected === sodium.to_hex(bytes).toLowerCase());

    const deserialised = Proteus.message.Message.deserialise(bytes.buffer);
    assert(deserialised.constructor === Proteus.message.HeaderMessage);
    assert(sodium.to_hex(deserialised.header) === sodium.to_hex(hd));
  });

  it('should serialise and deserialise a PreKeyMessage correctly', () => {
    const expected = '02a400181801a1005820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02a100a1005820a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a003a200a1004501020304050145060708090a';

    const hd = new Uint8Array([1, 2, 3, 4, 5]);
    const hmsg = Proteus.message.HeaderMessage.new(
      hd,
      new Uint8Array([6, 7, 8, 9, 10])
    );
    const pkmsg = Proteus.message.PreKeyMessage.new(24, bk, ik, hmsg);

    const bytes = new Uint8Array(pkmsg.serialise());
    assert(expected === sodium.to_hex(bytes).toLowerCase());

    const deserialised = Proteus.message.Message.deserialise(bytes.buffer);
    assert(deserialised.constructor === Proteus.message.PreKeyMessage);

    assert(deserialised.base_key.fingerprint() === bk.fingerprint());
    assert(deserialised.identity_key.fingerprint() === ik.fingerprint());

    assert(sodium.to_hex(deserialised.message.header) === sodium.to_hex(hd));
  });
});
