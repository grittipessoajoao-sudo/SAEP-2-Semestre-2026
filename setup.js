'use strict';

const { randomBytes } = require('node:crypto');
const { writeFileSync, existsSync } = require('node:fs');
const path = require('node:path');

const environmentPath = path.join(__dirname, '.env');
if (existsSync(environmentPath)) {
  console.log('.env já existe; nenhuma configuração foi alterada.');
  process.exit(0);
}

const encryptionKey = randomBytes(32).toString('hex');
writeFileSync(environmentPath, `PORT=3000\nCPF_ENCRYPTION_KEY=${encryptionKey}\n`, { flag: 'wx', mode: 0o600 });
console.log('Configuração local criada. A chave de cifragem foi gravada apenas em .env.');