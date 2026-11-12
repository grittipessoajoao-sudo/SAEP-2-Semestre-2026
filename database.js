'use strict';

const { DatabaseSync } = require('node:sqlite');
const { hashPassword } = require('./security');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'atendente' CHECK (role IN ('admin', 'atendente')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tutors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  cpf_encrypted TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tutor_id INTEGER NOT NULL REFERENCES tutors(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  name TEXT NOT NULL,
  species TEXT NOT NULL,
  breed TEXT NOT NULL DEFAULT '',
  birth_date TEXT NOT NULL DEFAULT '',
  sex TEXT NOT NULL DEFAULT '' CHECK (sex IN ('', 'Fêmea', 'Macho')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pet_id INTEGER NOT NULL REFERENCES pets(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  appointment_date TEXT NOT NULL,
  appointment_time TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Agendado' CHECK (status IN ('Agendado', 'Concluído', 'Cancelado')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pets_tutor_id ON pets(tutor_id);
CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date, appointment_time);
`;

function initializeDatabase(databasePath, cpfCipher) {
  const db = new DatabaseSync(databasePath);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);

  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (userCount === 0) seedDatabase(db, cpfCipher);
  return db;
}

function seedDatabase(db, cpfCipher) {
  const insertUser = db.prepare(
    'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
  );
  insertUser.run('João', 'joao@gmail.com', hashPassword('Vet@2026'), 'admin');
  insertUser.run('Rafael Lima', 'rafael@clinicavet.local', hashPassword('Vet@2026!'), 'atendente');
  insertUser.run('Camila Souza', 'camila@clinicavet.local', hashPassword('Vet@2026!'), 'atendente');

  const insertTutor = db.prepare(
    'INSERT INTO tutors (name, cpf_encrypted, phone, email, address) VALUES (?, ?, ?, ?, ?)',
  );
  insertTutor.run('Ana Martins', cpfCipher.encrypt('52998224725'), '(11) 99912-3456', 'ana@email.com', 'Rua das Flores, 120');
  insertTutor.run('Bruno Almeida', cpfCipher.encrypt('11144477735'), '(11) 98876-5432', 'bruno@email.com', 'Av. Central, 45');
  insertTutor.run('Carla Nogueira', cpfCipher.encrypt('93541134780'), '(11) 97765-4321', 'carla@email.com', 'Rua do Parque, 8');

  const insertPet = db.prepare(
    'INSERT INTO pets (tutor_id, name, species, breed, birth_date, sex) VALUES (?, ?, ?, ?, ?, ?)',
  );
  insertPet.run(1, 'Luna', 'Cão', 'Golden Retriever', '2021-04-12', 'Fêmea');
  insertPet.run(2, 'Nino', 'Gato', 'Siamês', '2022-09-03', 'Macho');
  insertPet.run(3, 'Pipoca', 'Coelho', 'Mini lop', '2023-02-20', 'Fêmea');

  const insertAppointment = db.prepare(
    'INSERT INTO appointments (pet_id, appointment_date, appointment_time, reason, status) VALUES (?, ?, ?, ?, ?)',
  );
  insertAppointment.run(1, '2026-11-14', '09:00', 'Consulta de rotina', 'Agendado');
  insertAppointment.run(2, '2026-11-14', '10:30', 'Vacinação', 'Agendado');
  insertAppointment.run(3, '2026-11-16', '14:00', 'Avaliação odontológica', 'Agendado');
}

module.exports = { initializeDatabase };