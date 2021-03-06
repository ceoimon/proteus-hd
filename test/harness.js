process.env.NODE_PATH = './src';
require('module').Module._initPaths();

assert = require('chai').assert;

global.sodium = require('libsodium-wrappers-sumo');

Proteus = require('proteus');
Proteus.derived = {
  DerivedSecrets: require('proteus/derived/DerivedSecrets'),
  CipherKey: require('proteus/derived/CipherKey'),
  HeadKey: require('proteus/derived/HeadKey'),
  MacKey: require('proteus/derived/MacKey')
};

Proteus.util = {
  KeyDerivationUtil: require('proteus/util/KeyDerivationUtil'),
  ArrayUtil: require('proteus/util/ArrayUtil'),
  MemoryUtil: require('proteus/util/MemoryUtil'),
  TypeUtil: require('proteus/util/TypeUtil')
};
