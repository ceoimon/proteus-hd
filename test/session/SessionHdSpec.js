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

class TestStore extends Proteus.session.PreKeyStore {
  constructor(prekeys) {
    super();
    this.prekeys = prekeys;
  }

  get_prekey(prekey_id) {
    return new Promise((resolve, reject) => {
      resolve(this.prekeys[prekey_id]);
    });
  }

  remove(prekey_id) {
    return new Promise((resolve, reject) => {
      delete this.prekeys[prekey_id];
      resolve();
    });
  }
}

const assert_init_from_message = (ident, store, message, expected) => {
  return new Promise((resolve, reject) => {
    Proteus.session.SessionHd.init_from_message(ident, store, message)
      .then((messageArray) => {
        const [session, _message] = messageArray;
        assert.strictEqual(sodium.to_string(_message), expected);
        resolve(session);
      })
      .catch((err) => {
        reject(err);
      });
  });
};

const assert_decrypt = (expected, decryptedPromise) => {
  return new Promise((resolve, reject) => {
    decryptedPromise.then((actual) => {
      assert.strictEqual(expected, sodium.to_string(actual));
      resolve();
    })
      .catch((err) => {
        reject(err);
      });
  });
};

const assert_prev_count = (session, expected) => {
  assert.strictEqual(
    expected,
    session.session_states[0].prev_counter
  );
};

const assert_serialise_deserialise = (local_identity, session) => {
  const bytes = session.serialise();

  const deser = Proteus.session.SessionHd.deserialise(local_identity, bytes);
  const deser_bytes = deser.serialise();

  assert.deepEqual(
    sodium.to_hex(new Uint8Array(bytes)),
    sodium.to_hex(new Uint8Array(deser_bytes))
  );
};

describe('SessionHd', () => {
  it('can be serialised and deserialised to/from CBOR', () => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((alice) => {
        assert(alice.session_states[0].recv_chains.length === 1);
        assert_serialise_deserialise(alice_ident, alice);
      });
  });

  it('encrypts and decrypts messages', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let hello_bob_delayed = null;
    let hello_alice = null;
    let ping_bob_1 = null;
    let ping_bob_2 = null;
    let pong_alice = null;

    Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;

        assert(alice.session_states[0].recv_chains.length === 1);

        return Promise.all(['Hello Bob!', 'Hello delay!'].map((text) => alice.encrypt(text)));
      })
      .then((msgs) => {
        [hello_bob, hello_bob_delayed] = msgs;

        assert(Object.keys(alice.session_states).length === 1);
        assert(alice.session_states[0].recv_chains.length === 1);

        return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
      })
      .then((session) => {
        bob = session;

        assert(Object.keys(bob.session_states).length === 1);
        assert(bob.session_states[0].recv_chains.length === 1);

        return bob.encrypt('Hello Alice!');
      })
      .then((message) => {
        hello_alice = message;
        return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
      })
      .then(() => {
        assert(alice.pending_prekey === null);
        assert(alice.session_states[0].recv_chains.length === 2);
        assert(alice.remote_identity.fingerprint() === bob.local_identity.public_key.fingerprint());

        return Promise.all(['Ping1!', 'Ping2!'].map((text) => alice.encrypt(text)));
      })
      .then((msgs) => {
        [ping_bob_1, ping_bob_2] = msgs;

        assert_prev_count(alice, 2);

        assert(ping_bob_1.message instanceof Proteus.message.HeaderMessage);
        assert(ping_bob_2.message instanceof Proteus.message.HeaderMessage);

        return assert_decrypt('Ping1!', bob.decrypt(bob_store, ping_bob_1));
      })
      .then(() => {
        assert(bob.session_states[0].recv_chains.length === 2);
        return assert_decrypt('Ping2!', bob.decrypt(bob_store, ping_bob_2));
      })
      .then(() => {
        assert(bob.session_states[0].recv_chains.length === 2);
        return bob.encrypt('Pong!');
      })
      .then((message) => {
        pong_alice = message;
        assert_prev_count(bob, 1);
        return assert_decrypt('Pong!', alice.decrypt(alice_store, pong_alice));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains.length === 3);
        assert_prev_count(alice, 2);
        return assert_decrypt('Hello delay!', bob.decrypt(bob_store, hello_bob_delayed));
      })
      .then(() => {
        assert(bob.session_states[0].recv_chains.length === 2);
        assert_prev_count(bob, 1);

        assert_serialise_deserialise(alice_ident, alice);
        return assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should limit the number of receive chains', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((hello_bob) => assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!'))
      .then((session) => {
        bob = session;

        assert(alice.session_states[0].recv_chains.length === 1);
        assert(bob.session_states[0].recv_chains.length === 1);

        return Promise.all(
          Array.from(
            {length: Proteus.session.SessionHd.MAX_RECV_CHAINS * 2},
            () => {
              return new Promise((resolve, reject) => {
                return bob.encrypt('ping')
                  .then((message) => assert_decrypt('ping', alice.decrypt(alice_store, message)))
                  .then(() => alice.encrypt('pong'))
                  .then((message) => assert_decrypt('pong', bob.decrypt(bob_store, message)))
                  .then(() => {
                    assert.isAtMost(
                      alice.session_states[0].recv_chains.length,
                      Proteus.session.SessionHd.MAX_RECV_CHAINS
                    );
                    assert.isAtMost(
                      bob.session_states[0].recv_chains.length,
                      Proteus.session.SessionHd.MAX_RECV_CHAINS
                    );
                    resolve();
                  });
              });
            }
          )
        );
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should handle a counter mismatch', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let ciphertexts = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => assert_init_from_message(bob_ident, bob_store, message, 'Hello Bob!'))
      .then((session) => {
        bob = session;
        return Promise.all(
          ['Hello1', 'Hello2', 'Hello3', 'Hello4', 'Hello5'].map((text) => bob.encrypt(text))
        );
      })
      .then((encryptArray) => {
        ciphertexts = encryptArray;
        return assert_decrypt('Hello2', alice.decrypt(alice_store, ciphertexts[1]));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 1);
        assert_serialise_deserialise(alice_ident, alice);
        return assert_decrypt('Hello1', alice.decrypt(alice_store, ciphertexts[0]));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 0);
        return assert_decrypt('Hello5', alice.decrypt(alice_store, ciphertexts[4]));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 2);
        return assert_decrypt('Hello4', alice.decrypt(alice_store, ciphertexts[3]));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 1);
        return new Promise((resolve, reject) => {
          return alice.decrypt(alice_store, ciphertexts[3])
            .then(() => assert.fail('should have raised Proteus.errors.DecryptError.DuplicateMessage'))
            .catch((err) => {
              assert.instanceOf(err, Proteus.errors.DecryptError.DuplicateMessage);
              assert.strictEqual(err.code, Proteus.errors.DecryptError.CODE.CASE_209);
              resolve();
            });
        });
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 1);
        return assert_decrypt('Hello3', alice.decrypt(alice_store, ciphertexts[2]));
      })
      .then(() => {
        assert(alice.session_states[0].recv_chains[0].message_keys.length === 0);
        return Promise.all(ciphertexts.map((text) => {
          return new Promise((resolve, reject) => {
            return alice.decrypt(alice_store, text)
              /**
               * NOTE: When `message_keys.length` === 0, we try decrypt header
               * from current receiving chain's chain key index, thus trying to
               * decrypt previous messages will raise `HeaderDecryptionFailed`
               * instead of `DuplicateMessage`
               */
              .then(() => assert.fail('should have raised Proteus.errors.DecryptError.HeaderDecryptionFailed'))
              .catch((err) => {
                assert.instanceOf(err, Proteus.errors.DecryptError.HeaderDecryptionFailed);
                assert.strictEqual(err.code, Proteus.errors.DecryptError.CODE.CASE_216);
                resolve();
              });
          });
        }));
      })
      .then(() => {
        assert_serialise_deserialise(alice_ident, alice);
        assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should handle multiple prekey messages', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let hello_bob1 = null;
    let hello_bob2 = null;
    let hello_bob3 = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return Promise.all(
          ['Hello Bob1!', 'Hello Bob2!', 'Hello Bob3!'].map((text) => alice.encrypt(text))
        );
      })
      .then((message) => {
        [hello_bob1, hello_bob2, hello_bob3] = message;
        return assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!');
      })
      .then((session) => {
        bob = session;
        assert(bob.session_states.length === 1);
        return assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
      })
      .then(() => {
        assert(bob.session_states.length === 1);
        return assert_decrypt('Hello Bob3!', bob.decrypt(bob_store, hello_bob3));
      })
      .then(() => {
        assert(bob.session_states.length === 1);
        assert_serialise_deserialise(alice_ident, alice);
        return assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should handle simultaneous prekey messages', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(() => Proteus.keys.IdentityKeyPair.new());
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    const alice_prekey = alice_store.prekeys[0];
    const alice_bundle = Proteus.keys.PreKeyBundle.new(alice_ident.public_key, alice_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let hello_alice = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => {
        hello_bob = message;
        bob = Proteus.session.SessionHd.init_from_prekey(bob_ident, alice_bundle);
        return bob;
      })
      .then((session) => {
        bob = session;
        return bob.encrypt('Hello Alice!');
      })
      .then((message) => {
        hello_alice = message;
        return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
      })
      .then(() => {
        assert(bob.session_states.length === 2);
        return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
      })
      .then(() => {
        assert(alice.session_states.length === 2);
        return alice.encrypt('That was fast!');
      })
      /**
       * NOTE: since there is no session tags in header encryption mode anymore,
       * decrypt and encrypt **MUST NOT** running simultaneously.
       */
      // .then((message) => {
      //   assert_decrypt('That was fast!', bob.decrypt(bob_store, message));
      //   return bob.encrypt(':-)');
      // })
      .then(message => assert_decrypt('That was fast!', bob.decrypt(bob_store, message)))
      .then(() => bob.encrypt(':-)'))
      .then(message => assert_decrypt(':-)', alice.decrypt(alice_store, message)))
      .then(() => {
        assert_serialise_deserialise(alice_ident, alice);
        return assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should handle simultaneous repeated messages', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    const alice_prekey = alice_store.prekeys[0];
    const alice_bundle = Proteus.keys.PreKeyBundle.new(alice_ident.public_key, alice_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let echo_bob1 = null;
    let echo_bob2 = null;
    let stop_bob = null;
    let hello_alice = null;
    let echo_alice1 = null;
    let echo_alice2 = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => {
        hello_bob = message;
        return Proteus.session.SessionHd.init_from_prekey(bob_ident, alice_bundle);
      })
      .then((session) => {
        bob = session;
        return bob.encrypt('Hello Alice!');
      })
      .then((message) => {
        hello_alice = message;
        return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
      })
      .then(() => assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice)))
      .then(() => alice.encrypt('Echo Bob1!'))
      .then((message) => {
        echo_bob1 = message;
        return bob.encrypt('Echo Alice1!');
      })
      .then((message) => {
        echo_alice1 = message;

        return assert_decrypt('Echo Bob1!', bob.decrypt(bob_store, echo_bob1));
      })
      .then(() => {
        assert(bob.session_states.length === 2);
        return assert_decrypt('Echo Alice1!', alice.decrypt(alice_store, echo_alice1));
      })
      .then(() => {
        assert(alice.session_states.length === 2);
        return alice.encrypt('Echo Bob2!');
      })
      .then((message) => {
        echo_bob2 = message;
        return bob.encrypt('Echo Alice2!');
      })
      .then((message) => {
        echo_alice2 = message;
        return assert_decrypt('Echo Bob2!', bob.decrypt(bob_store, echo_bob2));
      })
      .then(() => {
        assert(bob.session_states.length === 2);
        return assert_decrypt('Echo Alice2!', alice.decrypt(alice_store, echo_alice2));
      })
      .then(() => {
        assert(alice.session_states.length === 2);
        return alice.encrypt('Stop it!');
      })
      .then((message) => {
        stop_bob = message;
        return assert_decrypt('Stop it!', bob.decrypt(bob_store, stop_bob));
      })
      .then(() => bob.encrypt('OK'))
      .then((message) => {
        const answer_alice = message;
        return assert_decrypt('OK', alice.decrypt(alice_store, answer_alice));
      })
      .then(() => {
        assert_serialise_deserialise(alice_ident, alice);
        assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should handle mass communication', function (done) {
    this.timeout(0);

    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => {
        hello_bob = message;
        return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
      })
      .then((session) => {
        bob = session;

        // XXX: need to serialize/deserialize to/from CBOR here
        return Promise.all(Array.from({length: 999}, () => bob.encrypt('Hello Alice!')));
      })
      .then((messages) => {
        return Promise.all(
          messages.map((message) => assert_decrypt(
            'Hello Alice!',
            alice.decrypt(alice_store, Proteus.message.Envelope.deserialise(message.serialise()))
          ))
        );
      })
      .then(() => {
        assert_serialise_deserialise(alice_ident, alice);
        return assert_serialise_deserialise(bob_ident, bob);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should fail retry init from message', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let hello_bob = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => {
        hello_bob = message;
        return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
      })
      .then((session) => {
        return Proteus.session.SessionHd.init_from_message(bob_ident, bob_store, hello_bob);
      })
      .then(() => assert.fail('should have thrown Proteus.errors.ProteusError'))
      .catch((err) => {
        assert.instanceOf(err, Proteus.errors.ProteusError);
        assert.strictEqual(err.code, Proteus.errors.ProteusError.prototype.CODE.CASE_101);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('pathological case', function(done) {
    this.timeout(0);

    const num_alices = 32;
    let alices = null;
    let bob = null;

    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, num_alices));

    Promise.all(bob_store.prekeys.map((pk) => {
      const bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, pk);
      return Proteus.session.SessionHd.init_from_prekey(alice_ident, bundle);
    }))
      .then((session) => {
        alices = session;
        assert(alices.length === num_alices);
        return alices[0].encrypt('Hello Bob!');
      })
      .then((message) => assert_init_from_message(bob_ident, bob_store, message, 'Hello Bob!'))
      .then((session) => {
        bob = session;

        return Promise.all(alices.map((alice) => {
          return new Promise((resolve) => {
            Promise.all(
              Array.from({length: 900}, () => alice.encrypt('hello'))
            )
              .then(() => alice.encrypt('Hello Bob!'))
              .then((message) => resolve(assert_decrypt('Hello Bob!', bob.decrypt(bob_store, message))));
          });
        }));
      })
      .then(() => {
        assert(Object.keys(bob.session_states).length === num_alices);

        return Promise.all(alices.map((alice) => {
          return alice.encrypt('Hello Bob!')
            .then((message) => assert_decrypt('Hello Bob!', bob.decrypt(bob_store, message)));
        }));
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('skipped message keys', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [alice_store, bob_store] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob = null;
    let hello_alice0 = null;
    let hello_alice2 = null;
    let hello_bob0 = null;
    let hello_again0 = null;
    let hello_again1 = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((message) => {
        hello_bob = message;

        (() => {
          const s = alice.session_states[0];
          assert(s.recv_chains.length === 1);
          assert(s.recv_chains[0].chain_key.idx === 0);
          assert(s.send_chain.chain_key.idx === 1);
          assert(s.recv_chains[0].message_keys.length === 0);
        })();

        return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
      })
      .then((session) => {
        bob = session;

        (() => {
          // Normal exchange. Bob has created a new receive chain without skipped message keys.

          const state = bob.session_states[0];
          assert(state.recv_chains.length === 1);
          assert(state.recv_chains[0].chain_key.idx === 1);
          assert(state.send_chain.chain_key.idx === 0);
          return assert(state.recv_chains[0].message_keys.length === 0);
        })();

        return bob.encrypt('Hello0');
      })
      .then((message) => {
        hello_alice0 = message;
        return bob.encrypt('Hello1'); // unused result
      })
      .then(() => bob.encrypt('Hello2'))
      .then((message) => {
        hello_alice2 = message;
        return alice.decrypt(alice_store, hello_alice2);
      })
      .then(() => {
        (() => {
          // Alice has two skipped message keys in her new receive chain.

          const state = alice.session_states[0];
          assert(state.recv_chains.length === 2);
          assert(state.recv_chains[0].chain_key.idx === 3);
          assert(state.send_chain.chain_key.idx === 0);
          assert(state.recv_chains[0].message_keys.length === 2);
          assert(state.recv_chains[0].message_keys[0].counter === 0);
          assert(state.recv_chains[0].message_keys[1].counter === 1);
        })();

        return alice.encrypt('Hello0');
      })
      .then((message) => {
        hello_bob0 = message;
        return assert_decrypt('Hello0', bob.decrypt(bob_store, hello_bob0));
      })
      .then(() => {
        (() => {
          // For Bob everything is normal still. A new message from Alice means a
          // new receive chain has been created and again no skipped message keys.

          const state = bob.session_states[0];
          assert(state.recv_chains.length === 2);
          assert(state.recv_chains[0].chain_key.idx === 1);
          assert(state.send_chain.chain_key.idx === 0);
          assert(state.recv_chains[0].message_keys.length === 0);
        })();

        return assert_decrypt('Hello0', alice.decrypt(alice_store, hello_alice0));
      })
      .then(() => {
        (() => {
          // Alice received the first of the two missing messages. Therefore
          // only one message key is still skipped (counter value = 1).

          const state = alice.session_states[0];
          assert(state.recv_chains.length === 2);
          assert(state.recv_chains[0].message_keys.length === 1);
          assert(state.recv_chains[0].message_keys[0].counter === 1);
        })();

        return bob.encrypt('Again0');
      })
      .then((message) => {
        hello_again0 = message;
        return bob.encrypt('Again1');
      })
      .then((message) => {
        hello_again1 = message;
        return assert_decrypt('Again1', alice.decrypt(alice_store, hello_again1));
      })
      .then(() => {
        (() => {

        // Alice received the first of the two missing messages. Therefore
        // only one message key is still skipped (counter value = 1).

          const state = alice.session_states[0];
          assert(state.recv_chains.length === 3);
          assert(state.recv_chains[0].message_keys.length === 1);
          assert(state.recv_chains[1].message_keys.length === 1);
          assert(state.recv_chains[0].message_keys[0].counter === 0);
          assert(state.recv_chains[1].message_keys[0].counter === 1);
        })();

        return assert_decrypt('Again0', alice.decrypt(alice_store, hello_again0));
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('replaced prekeys', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [bob_store1, bob_store2] = [0, 1, 2].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 1))
    );

    const bob_prekey = bob_store1.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob1 = null;
    let hello_bob2 = null;
    let hello_bob3 = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob1!');
      })
      .then((message) => {
        hello_bob1 = message;
        return assert_init_from_message(bob_ident, bob_store1, hello_bob1, 'Hello Bob1!');
      })
      .then((session) => {
        bob = session;
        assert(bob.session_states.length === 1);
        return alice.encrypt('Hello Bob2!');
      })
      .then((message) => {
        hello_bob2 = message;
        assert_decrypt('Hello Bob2!', bob.decrypt(bob_store1, hello_bob2));
        assert(bob.session_states.length === 1);
        return alice.encrypt('Hello Bob3!');
      })
      .then((message) => {
        hello_bob3 = message;
        assert_decrypt('Hello Bob3!', bob.decrypt(bob_store2, hello_bob3));
        assert(bob.session_states.length === 1);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('max counter gap', function(done) {
    this.timeout(0);

    const [alice_ident, bob_ident] = [0, 1].map(() => Proteus.keys.IdentityKeyPair.new());

    let keys = [];
    keys[Proteus.keys.PreKey.MAX_PREKEY_ID] = Proteus.keys.PreKey.last_resort();
    const bob_store = new TestStore(keys);

    const bob_prekey = bob_store.prekeys[Proteus.keys.PreKey.MAX_PREKEY_ID];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle)
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob1!');
      })
      .then((hello_bob1) => assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!'))
      .then((session) => {
        bob = session;
        assert(bob.session_states.length === 1);

        return Promise.all(Array.from({length: 1001}, () => {
          return new Promise((resolve, reject) => {
            return alice.encrypt('Hello Bob2!')
              .then((hello_bob2) => {
                assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
                assert.strictEqual(bob.session_states.length, 1);
                resolve();
              });
          });
        }));
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should limit the number of sessions', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, (Proteus.session.SessionHd.MAX_SESSION_STATES + 2)));

    const bob_bundle = (index, store) => Proteus.keys.PreKeyBundle.new(bob_ident.public_key, store.prekeys[index]);

    let alice = null;
    let bob = null;
    let hello_bob = null;

    return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle(1, bob_store))
      .then((session) => {
        alice = session;
        return alice.encrypt('Hello Bob!');
      })
      .then((_hello_bob) => assert_init_from_message(bob_ident, bob_store, _hello_bob, 'Hello Bob!'))
      .then((session) => {
        bob = session;

        assert(bob.session_states.length === 1);

        return Promise.all(
          Array.from(
            {length: Proteus.session.SessionHd.MAX_SESSION_STATES},
            (obj, index) => {
              return Proteus.session.SessionHd.init_from_prekey(alice_ident, bob_bundle((index + 2), bob_store))
                .then((_session) => {
                  alice = _session;
                  return alice.encrypt('Hello Bob!');
                })
                .then((message) => {
                  hello_bob = message;
                  assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
                });
            }
          )
        );
      })
      .then(() => {
        assert.isAtMost(alice.session_states.length, Proteus.session.SessionHd.MAX_SESSION_STATES);
        assert.isAtMost(bob.session_states.length, Proteus.session.SessionHd.MAX_SESSION_STATES);
      })
      .then(() => {
        done();
      })
      .catch((err) => {
        done(err);
      });
  });
});
