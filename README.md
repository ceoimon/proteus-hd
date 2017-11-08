# Proteus-HD

*NOTE: Using header encryption will make message decryption process much slower! You may want to use [Proteus.js](https://github.com/wireapp/proteus.js) in most case.*

While [Proteus.js](https://github.com/wireapp/proteus.js) is an implementation of the [Signal Protocol](https://signal.org/docs/) without header encryption, Proteus-HD take advantage of the [header encryption variant of Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption) to make communication more secure.


## Build Status

[![Build Status](https://travis-ci.org/ceoimon/proteus-hd.svg?branch=header_encryption_only)](https://travis-ci.org/ceoimon/proteus-hd)

## Installation

### Node.js

```bash
yarn add proteus-hd
```

### Browser

Use a module bundler or [UMD](https://github.com/umdjs/umd) builds in the [`dist` folder](https://unpkg.com/proteus-hd/dist/)

## Usage

### Browser

- [index.html](./examples/browser.html)

### Node.js

- [index.js](./examples/node/index.js)

### TypeScript

```typescript
import * as Proteus from 'proteus-hd';
const identity: Proteus.keys.IdentityKeyPair = Proteus.keys.IdentityKeyPair.new();
```
