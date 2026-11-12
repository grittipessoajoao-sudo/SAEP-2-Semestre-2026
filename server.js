'use strict';

const http = require('node:http');
const { randomBytes } = require('node:crypto');
const path = require('node:path');
const { mkdirSync } = require('node:fs');
const { readFile } = require('node:fs/promises');
const { initializeDatabase } = require('./database');
const { createCpfCipher, isValidCpf, maskCpf, normalizeCpf, verifyPassword } = require('./security');

const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_MS = 30 * 60 * 1000;
const ROOT = __dirname;
const dbPath = process.env.DATABASE_PATH || path.join(ROOT, 'data', 'clinicavet.sqlite');
mkdirSync(path.dirname(dbPath), { recursive: true });
const encryptionKey = process.env.CPF_ENCRYPTION_KEY;
if (!encryptionKey) {
  console.error('Defina CPF_ENCRYPTION_KEY com uma chave aleatória de 64 caracteres hexadecimais.');
  process.exit(1);
}

const cpfCipher = createCpfCipher(encryptionKey);
const db = initializeDatabase(dbPath, cpfCipher);
const sessions = new Map();
const loginFailures = new Map();

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function randomToken() {
  return randomBytes(32).toString('base64url');
}

function cookieValue(request, name) {
  const cookies = request.headers.cookie || '';
  for (const item of cookies.split(';')) {
    const [key, ...value] = item.trim().split('=');
    if (key === name) return value.join('=');
  }
  return '';
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  response.setHeader('Set-Cookie', `clinicavet_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure}`);
}

function newSession() {
  return { csrf: randomToken(), expiresAt: Date.now() + SESSION_TTL_MS, user: null };
}

function getSession(request, response, create = false) {
  const token = cookieValue(request, 'clinicavet_session');
  const session = sessions.get(token);
  if (session && session.expiresAt > Date.now()) {
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    setSessionCookie(response, token);
    return { token, session };
  }
  if (token) sessions.delete(token);
  if (!create) return null;

  const nextToken = randomToken();
  const nextSession = newSession();
  sessions.set(nextToken, nextSession);
  setSessionCookie(response, nextToken);
  return { token: nextToken, session: nextSession };
}

function send(response, status, body, contentType = 'text/html; charset=utf-8') {
  response.writeHead(status, {
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'",
    'Cache-Control': 'no-store',
  });
  response.end(body);
}

function redirect(response, location) {
  response.writeHead(303, { Location: location, 'Cache-Control': 'no-store' });
  response.end();
}

function layout(title, content, session, currentPath, message = '') {
  const user = session?.user;
  const navigation = [
    ['/tutores', 'Tutores'],
    ['/pets', 'Pets'],
    ['/agendamentos', 'Agendamentos'],
  ].map(([href, label]) => `<a class="nav-link${currentPath === href ? ' is-active' : ''}" href="${href}">${label}</a>`).join('');
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#183c35">
  <title>${escapeHtml(title)} | Vetora Clínica</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/" aria-label="Vetora Clínica, início"><span class="brand-mark">v.</span><span>vetora<span class="brand-light">/clínica</span></span></a>
    ${user ? `<nav class="main-nav" aria-label="Navegação principal">${navigation}</nav>
    <div class="user-area"><span class="user-avatar">${escapeHtml(user.name.split(' ').map((part) => part[0]).slice(0, 2).join(''))}</span><span class="user-name">${escapeHtml(user.name)}</span>
      <form method="post" action="/sair"><input type="hidden" name="_csrf" value="${session.csrf}"><button class="logout-button" type="submit" title="Sair do sistema" aria-label="Sair do sistema">Sair <span aria-hidden="true">↗</span></button></form>
    </div>` : ''}
  </header>
  <main class="page-shell">
    ${message ? `<div class="notice" role="status">${escapeHtml(message)}</div>` : ''}
    ${content}
  </main>
  <footer class="site-footer"><span>VETORA <span class="footer-dot">/</span> GESTÃO CLÍNICA</span><span>Dados protegidos · sessão expira após 30 min de inatividade</span></footer>
</body>
</html>`;
}

function csrfField(session) {
  return `<input type="hidden" name="_csrf" value="${session.csrf}">`;
}

function requireAuthentication(request, response) {
  const active = getSession(request, response);
  if (!active?.session.user) {
    redirect(response, '/login');
    return null;
  }
  return active.session;
}

function validateCsrf(body, session) {
  return Boolean(session && body._csrf && body._csrf === session.csrf);
}

async function readBody(request) {
  let raw = '';
  for await (const chunk of request) {
    raw += chunk;
    if (raw.length > 16_384) throw new Error('Requisição muito grande.');
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

function validDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function validTime(value) {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
}

function tutorRecords() {
  return db.prepare('SELECT * FROM tutors ORDER BY name COLLATE NOCASE').all().map((tutor) => ({
    ...tutor,
    cpf: cpfCipher.decrypt(tutor.cpf_encrypted),
  }));
}

function findDuplicateCpf(cpf, exceptId = 0) {
  const normalized = normalizeCpf(cpf);
  return tutorRecords().some((tutor) => tutor.id !== exceptId && normalizeCpf(tutor.cpf) === normalized);
}

function renderLogin(session, error = '') {
  return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#183c35"><title>Acesso | Vetora Clínica</title><link rel="stylesheet" href="/style.css"></head>
<body class="login-page"><main class="login-layout">
  <section class="login-aside"><a class="brand brand-inverse" href="/"><span class="brand-mark">v.</span><span>vetora<span class="brand-light">/clínica</span></span></a><p class="eyebrow">CUIDADO EM CADA DETALHE</p><h1>Uma rotina mais leve para quem cuida.</h1><p class="login-copy">Atendimentos, tutores e pacientes em um só lugar.</p><div class="aside-foot"><span>GESTÃO VETERINÁRIA</span><span>01 — 03</span></div></section>
  <section class="login-form-area"><div class="login-form-wrap"><p class="eyebrow">ÁREA DA EQUIPE</p><h2>Bem-vindo de volta</h2><p class="muted">Acesse sua conta para continuar.</p>
    ${error ? `<div class="notice notice-error" role="alert">${escapeHtml(error)}</div>` : ''}
    <form method="post" action="/login" class="form-stack">${csrfField(session)}
      <label>E-mail<input type="email" name="email" autocomplete="username" required autofocus placeholder="voce@clinica.com"></label>
      <label>Senha<input type="password" name="password" autocomplete="current-password" required placeholder="Sua senha"></label>
      <button class="button button-primary button-wide" type="submit">Entrar <span aria-hidden="true">→</span></button>
    </form><p class="login-security"><span class="security-dot"></span> Conexão protegida · sessão individual</p>
  </div></section>
</main></body></html>`;
}

function renderDashboard(session, query) {
  const countTutors = db.prepare('SELECT COUNT(*) AS count FROM tutors').get().count;
  const countPets = db.prepare('SELECT COUNT(*) AS count FROM pets').get().count;
  const countAppointments = db.prepare("SELECT COUNT(*) AS count FROM appointments WHERE appointment_date = date('now', 'localtime') AND status = 'Agendado'").get().count;
  const nextAppointments = db.prepare(`
    SELECT a.appointment_date, a.appointment_time, a.reason, p.name AS pet_name, t.name AS tutor_name
    FROM appointments a JOIN pets p ON p.id = a.pet_id JOIN tutors t ON t.id = p.tutor_id
    WHERE a.appointment_date >= date('now', 'localtime') AND a.status = 'Agendado'
    ORDER BY a.appointment_date, a.appointment_time LIMIT 4
  `).all();
  const items = nextAppointments.length ? nextAppointments.map((item) => `<tr><td>${escapeHtml(formatDate(item.appointment_date))}<small>${escapeHtml(item.appointment_time)}</small></td><td><strong>${escapeHtml(item.pet_name)}</strong><small>${escapeHtml(item.tutor_name)}</small></td><td>${escapeHtml(item.reason)}</td></tr>`).join('') : '<tr><td colspan="3" class="empty-state">Nenhum atendimento futuro cadastrado.</td></tr>';
  const todayLabel = new Intl.DateTimeFormat('pt-BR', { weekday: 'long', day: 'numeric', month: 'long' }).format(new Date()).toLocaleUpperCase('pt-BR');
  return layout('Visão geral', `<section class="page-heading"><div><p class="eyebrow">${escapeHtml(todayLabel)}</p><h1>Bom trabalho, ${escapeHtml(session.user.name.split(' ')[0])}.</h1><p class="muted">Aqui está o panorama da clínica.</p></div><a class="button button-primary" href="/agendamentos">Ver agenda <span aria-hidden="true">→</span></a></section>
    <section class="stats-grid" aria-label="Resumo da clínica"><article class="stat stat-green"><span>TUTORES CADASTRADOS</span><strong>${countTutors.toString().padStart(2, '0')}</strong><a href="/tutores">Abrir cadastro <span>↗</span></a></article><article class="stat stat-rose"><span>PACIENTES ATIVOS</span><strong>${countPets.toString().padStart(2, '0')}</strong><a href="/pets">Ver pacientes <span>↗</span></a></article><article class="stat stat-gold"><span>CONSULTAS DE HOJE</span><strong>${countAppointments.toString().padStart(2, '0')}</strong><a href="/agendamentos">Abrir agenda <span>↗</span></a></article></section>
    <section class="section-block"><div class="section-heading"><div><p class="eyebrow">PRÓXIMOS ATENDIMENTOS</p><h2>Agenda da clínica</h2></div><a class="text-link" href="/agendamentos">Ver todos <span>→</span></a></div><div class="table-wrap"><table><thead><tr><th>DATA / HORA</th><th>PACIENTE / TUTOR</th><th>MOTIVO</th></tr></thead><tbody>${items}</tbody></table></div></section>`, session, '/', query.get('mensagem') || '');
}

function formatDate(value) {
  if (!validDate(value)) return value;
  const [year, month, day] = value.split('-');
  return `${day}/${month}/${year}`;
}

function renderTutors(session, query) {
  const term = (query.get('busca') || '').trim();
  const digitTerm = normalizeCpf(term);
  const tutors = tutorRecords().filter((tutor) => !term || [tutor.name, tutor.phone, tutor.email, tutor.address].some((value) => value.toLocaleLowerCase('pt-BR').includes(term.toLocaleLowerCase('pt-BR'))) || (digitTerm.length > 0 && normalizeCpf(tutor.cpf).includes(digitTerm)));
  const rows = tutors.length ? tutors.map((tutor) => `<tr><td><strong>${escapeHtml(tutor.name)}</strong><small>${escapeHtml(tutor.email || 'Sem e-mail')}</small></td><td>${escapeHtml(maskCpf(tutor.cpf))}</td><td>${escapeHtml(tutor.phone)}</td><td>${escapeHtml(tutor.address || '—')}</td><td><details class="edit-details"><summary class="icon-action" aria-label="Editar ${escapeHtml(tutor.name)}" title="Editar tutor">Editar</summary><form method="post" action="/tutores/${tutor.id}/editar" class="edit-popover">${csrfField(session)}<h3>Editar tutor</h3>${tutorFields(tutor, true)}<button class="button button-primary button-small" type="submit">Salvar alterações</button></form></details></td></tr>`).join('') : '<tr><td colspan="5" class="empty-state">Nenhum tutor corresponde à busca.</td></tr>';
  return layout('Tutores', `<section class="page-heading"><div><p class="eyebrow">CADASTROS / TUTORES</p><h1>Quem cuida deles.</h1><p class="muted">Dados dos responsáveis e contato da clínica.</p></div><span class="record-count">${tutors.length} ${tutors.length === 1 ? 'tutor' : 'tutores'}</span></section>
    <section class="section-block"><form class="search-row" method="get" action="/tutores"><label class="search-field"><span aria-hidden="true">⌕</span><input type="search" name="busca" value="${escapeHtml(term)}" placeholder="Buscar por nome, CPF, telefone ou e-mail" aria-label="Termo para buscar tutor"></label><button class="button button-dark" type="submit">Buscar</button>${term ? '<a class="button button-quiet" href="/tutores">Limpar</a>' : ''}</form><div class="table-wrap"><table><thead><tr><th>TUTOR</th><th>CPF (PROTEGIDO)</th><th>TELEFONE</th><th>ENDEREÇO</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>
    <section class="section-block form-section"><div class="section-heading"><div><p class="eyebrow">NOVO CADASTRO</p><h2>Adicionar tutor</h2></div></div><form method="post" action="/tutores/novo" class="form-grid">${csrfField(session)}${tutorFields()}<div class="form-actions"><button class="button button-primary" type="submit">Salvar tutor <span aria-hidden="true">→</span></button></div></form></section>`, session, '/tutores', query.get('mensagem') || '');
}

function tutorFields(tutor = {}, compact = false) {
  const fieldClass = compact ? 'compact-fields' : 'form-grid';
  return `<div class="${fieldClass}"><label>Nome completo<input name="name" value="${escapeHtml(tutor.name || '')}" required maxlength="120" autocomplete="name"></label><label>CPF<input name="cpf" value="${compact ? '' : escapeHtml(tutor.cpf || '')}" ${compact ? '' : 'required'} inputmode="numeric" placeholder="${compact ? 'Deixe em branco para manter' : '000.000.000-00'}" maxlength="14"></label><label>Telefone<input name="phone" value="${escapeHtml(tutor.phone || '')}" required maxlength="30" autocomplete="tel"></label><label>E-mail<input type="email" name="email" value="${escapeHtml(tutor.email || '')}" maxlength="160" autocomplete="email"></label><label class="field-wide">Endereço<input name="address" value="${escapeHtml(tutor.address || '')}" maxlength="240" autocomplete="street-address"></label></div>`;
}

function renderPets(session, query) {
  const pets = db.prepare(`SELECT p.*, t.name AS tutor_name FROM pets p JOIN tutors t ON t.id = p.tutor_id ORDER BY p.name COLLATE NOCASE`).all();
  const tutors = db.prepare('SELECT id, name FROM tutors ORDER BY name COLLATE NOCASE').all();
  const rows = pets.length ? pets.map((pet) => `<tr><td><strong>${escapeHtml(pet.name)}</strong><small>${escapeHtml(pet.breed || pet.species)}</small></td><td>${escapeHtml(pet.species)}</td><td>${escapeHtml(pet.sex || '—')}</td><td>${escapeHtml(pet.birth_date ? formatDate(pet.birth_date) : '—')}</td><td>${escapeHtml(pet.tutor_name)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-state">Nenhum pet cadastrado.</td></tr>';
  const tutorOptions = tutors.map((tutor) => `<option value="${tutor.id}">${escapeHtml(tutor.name)}</option>`).join('');
  return layout('Pets', `<section class="page-heading"><div><p class="eyebrow">CADASTROS / PACIENTES</p><h1>Pequenos pacientes.</h1><p class="muted">Cada pet vinculado ao seu tutor responsável.</p></div><span class="record-count">${pets.length} ${pets.length === 1 ? 'pet' : 'pets'}</span></section>
    <section class="section-block"><div class="table-wrap"><table><thead><tr><th>PACIENTE</th><th>ESPÉCIE</th><th>SEXO</th><th>NASCIMENTO</th><th>TUTOR RESPONSÁVEL</th></tr></thead><tbody>${rows}</tbody></table></div></section>
    <section class="section-block form-section"><div class="section-heading"><div><p class="eyebrow">NOVO CADASTRO</p><h2>Adicionar pet</h2></div></div>${tutors.length ? `<form method="post" action="/pets/novo" class="form-grid">${csrfField(session)}<label>Nome do pet<input name="name" required maxlength="100"></label><label>Espécie<select name="species" required><option value="">Selecione</option><option>Cão</option><option>Gato</option><option>Coelho</option><option>Ave</option><option>Outro</option></select></label><label>Raça<input name="breed" maxlength="100"></label><label>Data de nascimento<input name="birth_date" type="date"></label><label>Sexo<select name="sex"><option value="">Não informado</option><option>Fêmea</option><option>Macho</option></select></label><label>Tutor responsável<select name="tutor_id" required><option value="">Selecione um tutor</option>${tutorOptions}</select></label><div class="form-actions"><button class="button button-primary" type="submit">Salvar pet <span aria-hidden="true">→</span></button></div></form>` : '<p class="empty-state">Cadastre um tutor antes de adicionar um pet.</p>'}</section>`, session, '/pets', query.get('mensagem') || '');
}

  function renderAppointments(session, query) {
  const appointments = db.prepare(`
    SELECT a.id, a.appointment_date, a.appointment_time, a.reason, a.status,
      p.name AS pet_name, p.species, p.breed, p.birth_date, p.sex,
      t.name AS tutor_name, t.cpf_encrypted, t.phone, t.email, t.address
    FROM appointments a JOIN pets p ON p.id = a.pet_id JOIN tutors t ON t.id = p.tutor_id
    ORDER BY a.appointment_date, a.appointment_time
  `).all();
  const rows = appointments.length ? appointments.map((item) => `<tr><td><strong>${escapeHtml(formatDate(item.appointment_date))}</strong><small>${escapeHtml(item.appointment_time)}</small><details class="edit-details date-edit"><summary class="text-link">Alterar data</summary><form method="post" action="/agendamentos/${item.id}/data" class="edit-popover date-popover">${csrfField(session)}<label>Nova data<input type="date" name="appointment_date" value="${escapeHtml(item.appointment_date)}" required></label><label>Novo horário<input type="time" name="appointment_time" value="${escapeHtml(item.appointment_time)}" required></label><button class="button button-primary button-small" type="submit">Salvar</button></form></details></td><td><strong>${escapeHtml(item.pet_name)}</strong><small>${escapeHtml([item.species, item.breed, item.sex, item.birth_date ? `Nasc. ${formatDate(item.birth_date)}` : ''].filter(Boolean).join(' · '))}</small></td><td><strong>${escapeHtml(item.tutor_name)}</strong><small>${escapeHtml(maskCpf(cpfCipher.decrypt(item.cpf_encrypted)))} · ${escapeHtml(item.phone)}</small><small>${escapeHtml(item.email || 'Sem e-mail')} · ${escapeHtml(item.address || 'Endereço não informado')}</small></td><td>${escapeHtml(item.reason || '—')}<small><span class="status-pill status-${item.status === 'Agendado' ? 'scheduled' : item.status === 'Concluído' ? 'done' : 'cancelled'}">${escapeHtml(item.status)}</span></small></td></tr>`).join('') : '<tr><td colspan="4" class="empty-state">Nenhum agendamento cadastrado.</td></tr>';
  const pets = db.prepare(`SELECT p.id, p.name, t.name AS tutor_name FROM pets p JOIN tutors t ON t.id = p.tutor_id ORDER BY p.name COLLATE NOCASE`).all();
  const petOptions = pets.map((pet) => `<option value="${pet.id}">${escapeHtml(pet.name)} · ${escapeHtml(pet.tutor_name)}</option>`).join('');
  const createForm = pets.length ? `<section class="section-block form-section"><div class="section-heading"><div><p class="eyebrow">NOVO ATENDIMENTO</p><h2>Adicionar à agenda</h2></div></div><form method="post" action="/agendamentos/novo" class="form-grid">${csrfField(session)}<label>Paciente<select name="pet_id" required><option value="">Selecione um pet</option>${petOptions}</select></label><label>Motivo<input name="reason" required maxlength="180" placeholder="Ex.: consulta de rotina"></label><label>Data<input name="appointment_date" type="date" required></label><label>Horário<input name="appointment_time" type="time" required></label><div class="form-actions"><button class="button button-primary" type="submit">Agendar consulta <span aria-hidden="true">→</span></button></div></form></section>` : '<section class="section-block form-section"><p class="empty-state">Cadastre um pet antes de criar um agendamento.</p></section>';
  return layout('Agendamentos', `<section class="page-heading"><div><p class="eyebrow">ROTINA / AGENDA</p><h1>Tempo bem cuidado.</h1><p class="muted">Atendimentos por data, com os dados do paciente e de quem acompanha.</p></div><span class="record-count">${appointments.length} ${appointments.length === 1 ? 'agendamento' : 'agendamentos'}</span></section>
    <section class="section-block"><div class="table-wrap"><table class="appointments-table"><thead><tr><th>DATA / HORA</th><th>PACIENTE</th><th>TUTOR / CONTATO</th><th>ATENDIMENTO</th></tr></thead><tbody>${rows}</tbody></table></div></section>${createForm}`, session, '/agendamentos', query.get('mensagem') || '');
}

async function handleRequest(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  if (request.method === 'GET' && pathname === '/style.css') {
    try {
      const css = await readFile(path.join(ROOT, 'public', 'style.css'));
      return send(response, 200, css, 'text/css; charset=utf-8');
    } catch {
      return send(response, 404, 'Not found', 'text/plain; charset=utf-8');
    }
  }

  let active = getSession(request, response);
  if (request.method === 'GET' && pathname === '/login') {
    active = active || getSession(request, response, true);
    return send(response, 200, renderLogin(active.session));
  }

  if (request.method === 'POST' && pathname === '/login') {
    let body;
    try { body = await readBody(request); } catch { return send(response, 400, 'Requisição inválida.', 'text/plain; charset=utf-8'); }
    if (!active || !validateCsrf(body, active.session)) {
      active = getSession(request, response, true);
      return send(response, 403, renderLogin(active.session, 'A sessão expirou. Atualize a página e tente novamente.'));
    }
    const clientAddress = request.socket.remoteAddress || 'unknown';
    const attempts = loginFailures.get(clientAddress) || { count: 0, blockedUntil: 0 };
    if (attempts.blockedUntil > Date.now()) {
      return send(response, 429, renderLogin(active.session, 'Muitas tentativas de acesso. Aguarde 15 minutos e tente novamente.'));
    }
    const user = db.prepare('SELECT id, name, email, password_hash, role FROM users WHERE email = ? COLLATE NOCASE').get((body.email || '').trim());
    if (!user || !verifyPassword(body.password || '', user.password_hash)) {
      attempts.count += 1;
      if (attempts.count >= 5) {
        attempts.count = 0;
        attempts.blockedUntil = Date.now() + 15 * 60 * 1000;
      }
      loginFailures.set(clientAddress, attempts);
      return send(response, 401, renderLogin(active.session, 'E-mail ou senha inválidos. Confira os dados e tente novamente.'));
    }
    loginFailures.delete(clientAddress);
    sessions.delete(active.token);
    const token = randomToken();
    const session = newSession();
    session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    sessions.set(token, session);
    setSessionCookie(response, token);
    return redirect(response, '/');
  }

  if (pathname === '/sair' && request.method === 'POST') {
    let body;
    try { body = await readBody(request); } catch { return send(response, 400, 'Requisição inválida.', 'text/plain; charset=utf-8'); }
    if (!active || !validateCsrf(body, active.session)) return redirect(response, '/login');
    sessions.delete(active.token);
    response.setHeader('Set-Cookie', 'clinicavet_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    return redirect(response, '/login');
  }

  const session = requireAuthentication(request, response);
  if (!session) return;

  if (request.method === 'GET' && pathname === '/') {
    return send(response, 200, renderDashboard(session, url.searchParams));
  }
  if (request.method === 'GET' && pathname === '/tutores') {
    return send(response, 200, renderTutors(session, url.searchParams));
  }
  if (request.method === 'GET' && pathname === '/pets') {
    return send(response, 200, renderPets(session, url.searchParams));
  }
  if (request.method === 'GET' && pathname === '/agendamentos') {
    return send(response, 200, renderAppointments(session, url.searchParams));
  }

  if (request.method === 'POST') {
    let body;
    try { body = await readBody(request); } catch { return send(response, 400, 'Requisição inválida.', 'text/plain; charset=utf-8'); }
    if (!validateCsrf(body, session)) return send(response, 403, 'A sessão expirou. Atualize a página e tente novamente.');

    if (pathname === '/tutores/novo' || /^\/tutores\/\d+\/editar$/.test(pathname)) {
      const tutorId = pathname === '/tutores/novo' ? 0 : Number(pathname.split('/')[2]);
      const providedCpf = normalizeCpf(body.cpf);
      const existingTutor = tutorId ? db.prepare('SELECT id, cpf_encrypted FROM tutors WHERE id = ?').get(tutorId) : null;
      if (tutorId && !existingTutor) return send(response, 404, 'Tutor não encontrado.');
      const cpf = providedCpf || (existingTutor ? cpfCipher.decrypt(existingTutor.cpf_encrypted) : '');
      const name = (body.name || '').trim();
      const phone = (body.phone || '').trim();
      const email = (body.email || '').trim();
      const address = (body.address || '').trim();
      const returnPath = '/tutores';
      if (!name || !phone || !isValidCpf(cpf)) return redirect(response, `${returnPath}?mensagem=${encodeURIComponent('Informe nome, telefone e um CPF válido.')}`);
      if (findDuplicateCpf(cpf, tutorId)) return redirect(response, `${returnPath}?mensagem=${encodeURIComponent('Já existe um tutor cadastrado com este CPF.')}`);
      const encryptedCpf = providedCpf ? cpfCipher.encrypt(cpf) : existingTutor.cpf_encrypted;
      if (tutorId) {
        const result = db.prepare(`UPDATE tutors SET name = ?, cpf_encrypted = ?, phone = ?, email = ?, address = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(name, encryptedCpf, phone, email, address, tutorId);
        if (!result.changes) return send(response, 404, 'Tutor não encontrado.');
        return redirect(response, `${returnPath}?mensagem=${encodeURIComponent('Dados do tutor atualizados.')}`);
      }
      db.prepare('INSERT INTO tutors (name, cpf_encrypted, phone, email, address) VALUES (?, ?, ?, ?, ?)').run(name, encryptedCpf, phone, email, address);
      return redirect(response, `${returnPath}?mensagem=${encodeURIComponent('Tutor cadastrado com sucesso.')}`);
    }

    if (pathname === '/pets/novo') {
      const name = (body.name || '').trim();
      const species = (body.species || '').trim();
      const tutorId = Number(body.tutor_id);
      const birthDate = body.birth_date || '';
      const allowedSex = ['', 'Fêmea', 'Macho'];
      const sex = allowedSex.includes(body.sex) ? body.sex : '';
      const tutorExists = db.prepare('SELECT id FROM tutors WHERE id = ?').get(tutorId);
      if (!name || !species || !tutorExists || (birthDate && !validDate(birthDate))) {
        return redirect(response, `/pets?mensagem=${encodeURIComponent('Confira os dados do pet e selecione um tutor cadastrado.')}`);
      }
      db.prepare('INSERT INTO pets (tutor_id, name, species, breed, birth_date, sex) VALUES (?, ?, ?, ?, ?, ?)').run(tutorId, name, species, (body.breed || '').trim(), birthDate, sex);
      return redirect(response, `/pets?mensagem=${encodeURIComponent('Pet cadastrado e associado ao tutor.')}`);
    }

    if (pathname === '/agendamentos/novo') {
      const petId = Number(body.pet_id);
      const appointmentDate = body.appointment_date || '';
      const appointmentTime = body.appointment_time || '';
      const petExists = db.prepare('SELECT id FROM pets WHERE id = ?').get(petId);
      if (!petExists || !validDate(appointmentDate) || !validTime(appointmentTime) || !(body.reason || '').trim()) {
        return redirect(response, `/agendamentos?mensagem=${encodeURIComponent('Confira paciente, motivo, data e horário do agendamento.')}`);
      }
      db.prepare('INSERT INTO appointments (pet_id, appointment_date, appointment_time, reason) VALUES (?, ?, ?, ?)').run(petId, appointmentDate, appointmentTime, body.reason.trim());
      return redirect(response, `/agendamentos?mensagem=${encodeURIComponent('Consulta adicionada à agenda.')}`);
    }

    const appointmentMatch = pathname.match(/^\/agendamentos\/(\d+)\/data$/);
    if (appointmentMatch) {
      const appointmentId = Number(appointmentMatch[1]);
      const date = body.appointment_date || '';
      const time = body.appointment_time || '';
      if (!validDate(date) || !validTime(time)) return redirect(response, `/agendamentos?mensagem=${encodeURIComponent('Informe uma data e um horário válidos.')}`);
      const result = db.prepare('UPDATE appointments SET appointment_date = ?, appointment_time = ? WHERE id = ?').run(date, time, appointmentId);
      if (!result.changes) return send(response, 404, 'Agendamento não encontrado.');
      return redirect(response, `/agendamentos?mensagem=${encodeURIComponent('Data e horário atualizados.')}`);
    }
  }

  return send(response, 404, layout('Não encontrado', '<section class="page-heading"><div><p class="eyebrow">ERRO 404</p><h1>Esta página não existe.</h1><a class="text-link" href="/">Voltar ao início →</a></div></section>', session, ''));
}

const server = http.createServer((request, response) => {
  handleRequest(request, response).catch((error) => {
    console.error(error);
    if (!response.headersSent) send(response, 500, 'Ocorreu um erro interno. Tente novamente.', 'text/plain; charset=utf-8');
    else response.end();
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Vetora Clínica disponível em http://localhost:${server.address().port}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);