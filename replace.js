'use strict';

const fs = require('fs');
const path = require('path');
const file = path.resolve(__dirname, 'dist/types.d.ts');
const regex = /^(module [^ ]+ {)$/gm;

fs.readFile(file, 'utf8', (err, content) => {
  if (err !== null) throw err;
  content = `import * as CBOR from 'wire-webapp-cbor';\n\n${content.replace(regex, 'export $1')}`;
  fs.writeFile(file, content, (e) => {
    if (e !== null) throw e;
  });
});
