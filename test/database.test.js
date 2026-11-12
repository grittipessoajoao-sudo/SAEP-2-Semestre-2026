'use strict';

const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { initializeDatabase } = require('../database');
const { createCpfCipher, hashPassword, isValidCpf, maskCpf, verifyPassword } = require('../security');

const KEY = 'a'.repeat(64);

test('CPF é cifrado com autenticidade e pode ser exibido mascarado', () => {
  const cipher = createCpfCipher(KEY);
  const encrypted = cipher.encrypt('52998224725');
  assert.notEqual(encrypted, '52998224725');
  assert.equal(cipher.decrypt(encrypted), '52998224725');
  assert.equal(maskCpf(cipher.decrypt(encrypted)), '***.***.***-25');
  assert.equal(isValidCpf('529.982.247-25'), true);
  assert.equal(isValidCpf('111.111.111-11'), false);
});

test('senha usa hash com salt e rejeita senha incorreta', () => {
  const storedHash = hashPassword('Vet@2026!');
  assert.notEqual(storedHash, 'Vet@2026!');
  assert.equal(verifyPassword('Vet@2026!', storedHash), true);
  assert.equal(verifyPassword('incorreta', storedHash), false);
});

test('banco inicializa as quatro tabelas com três registros e chaves estrangeiras válidas', (context) => {
  const folder = mkdtempSync(path.join(os.tmpdir(), 'clinicavet-'));
  const db = initializeDatabase(path.join(folder, 'test.sqlite'), createCpfCipher(KEY));
  context.after(() => {
    db.close();
    rmSync(folder, { recursive: true, force: true });
  });

  for (const table of ['users', 'tutors', 'pets', 'appointments']) {
    assert.equal(db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 3, table);
  }
  const passwordHashes = db.prepare('SELECT password_hash FROM users').all().map((row) => row.password_hash);
  assert.equal(new Set(passwordHashes).size, 3);
  const admin = db.prepare('SELECT email, password_hash FROM users WHERE role = ?').get('admin');
  assert.equal(admin.email, 'joao@gmail.com');
  assert.equal(verifyPassword('Vet@2026', admin.password_hash), true);
  assert.equal(db.prepare('PRAGMA foreign_key_check').all().length, 0);

  const storedCpf = db.prepare('SELECT cpf_encrypted FROM tutors WHERE id = 1').get().cpf_encrypted;
  assert.equal(storedCpf.includes('52998224725'), false);
});