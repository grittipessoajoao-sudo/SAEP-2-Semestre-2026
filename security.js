'use strict';

const {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} = require('node:crypto');

function createCpfCipher(keyHex) {
  if (!/^[\da-f]{64}$/i.test(keyHex || '')) {
    throw new Error('CPF_ENCRYPTION_KEY deve conter 64 caracteres hexadecimais.');
  }

  const key = Buffer.from(keyHex, 'hex');

  return {
    encrypt(cpf) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(cpf, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      return [iv, tag, encrypted].map((part) => part.toString('hex')).join(':');
    },
    decrypt(value) {
      const [ivHex, tagHex, encryptedHex] = value.split(':');
      if (!ivHex || !tagHex || !encryptedHex) {
        throw new Error('Formato de CPF criptografado inválido.');
      }
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      return Buffer.concat([
        decipher.update(Buffer.from(encryptedHex, 'hex')),
        decipher.final(),
      ]).toString('utf8');
    },
  };
}

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const [saltHex, hashHex] = storedHash.split(':');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function normalizeCpf(value) {
  return String(value || '').replace(/\D/g, '');
}

function isValidCpf(value) {
  const cpf = normalizeCpf(value);
  if (!/^\d{11}$/.test(cpf) || /^([\d])\1{10}$/.test(cpf)) return false;

  const digit = (length) => {
    let sum = 0;
    for (let index = 0; index < length; index += 1) {
      sum += Number(cpf[index]) * (length + 1 - index);
    }
    const remainder = (sum * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };

  return digit(9) === Number(cpf[9]) && digit(10) === Number(cpf[10]);
}

function maskCpf(cpf) {
  return `***.***.***-${normalizeCpf(cpf).slice(-2)}`;
}

module.exports = { createCpfCipher, hashPassword, isValidCpf, maskCpf, normalizeCpf, verifyPassword };