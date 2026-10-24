// PoodleHelp: сервер заявок с входом для приюта по общему паролю
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- простая загрузка .env (без лишних зависимостей)
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
  });
} catch (e) {}

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.STAFF_PASSWORD || '';   // пароль для сотрудников приюта (задаётся в настройках хостинга)
if (!PASSWORD) console.error('ВНИМАНИЕ: не задана переменная STAFF_PASSWORD, вход для приюта отключён.');

const DATA_FILE = path.join(__dirname, 'data.json');
let db = { applications: [], dogs: null }; // dogs: null = список ещё не менялся, показываем стандартных
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))); } catch (e) {}
const save = () => { fs.writeFileSync(DATA_FILE + '.tmp', JSON.stringify(db, null, 2)); fs.renameSync(DATA_FILE + '.tmp', DATA_FILE); };

const digits = v => String(v || '').replace(/\D/g, '').slice(-10);
const sha = v => crypto.createHash('sha256').update(String(v)).digest();

// --- ограничение частоты запросов
const hits = new Map();
function limit(key, max, ms) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < ms);
  if (arr.length >= max) return false;
  arr.push(now); hits.set(key, arr); return true;
}
setInterval(() => { const n = Date.now(); for (const [k, a] of hits) if (!a.some(t => n - t < 3600e3)) hits.delete(k); }, 600e3).unref();

const sessions = new Map();  // token -> { exp }

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// CORS: сайт на GitHub Pages обращается к серверу с другого адреса
const ALLOWED = (process.env.ALLOWED_ORIGIN || 'https://seris-moon.github.io').split(',').map(x => x.trim()).filter(Boolean);
app.use((req, res, next) => {
  const o = req.get('origin');
  if (o && ALLOWED.includes(o)) {
    res.set({ 'Access-Control-Allow-Origin': o, 'Vary': 'Origin',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS' });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  next();
});

function auth(req, res, next) {
  const t = (req.get('authorization') || '').replace(/^Bearer /, '');
  const s = sessions.get(t);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Требуется вход' });
  req.staff = s; next();
}

// ===== Вход приюта по паролю =====
app.post('/api/auth/login', (req, res) => {
  if (!PASSWORD) return res.status(503).json({ error: 'Пароль на сервере не настроен' });
  if (!limit('login:' + req.ip, 8, 600e3) || !limit('login:all', 100, 600e3))
    return res.status(429).json({ error: 'Слишком много попыток входа. Подождите 10 минут.' });
  const given = sha(String((req.body || {}).password || ''));
  if (!crypto.timingSafeEqual(given, sha(PASSWORD))) return res.status(401).json({ error: 'Неверный пароль' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { name: 'Сотрудник', exp: Date.now() + 8 * 3600e3 });
  res.json({ token, name: 'Сотрудник' });
});

app.post('/api/auth/logout', auth, (req, res) => {
  sessions.delete((req.get('authorization') || '').replace(/^Bearer /, ''));
  res.json({ ok: true });
});

// ===== Заявки =====
const OWNER_KEYS = ['name','phone','age','housing','yard','time_with_dog','experience','other_pets','children','schedule','training','finance','motivation','extra','dogId','dogName'];
const clip = (v, n) => String(v == null ? '' : v).slice(0, n);

app.post('/api/applications', (req, res) => {
  if (!limit('app:' + req.ip, 10, 3600e3)) return res.status(429).json({ error: 'Слишком много заявок' });
  const b = req.body || {};
  const owner = {};
  OWNER_KEYS.forEach(k => { owner[k] = clip((b.owner || {})[k], k === 'motivation' || k === 'extra' ? 1000 : 120); });
  if (!owner.name || digits(owner.phone).length < 10) return res.status(400).json({ error: 'Укажите имя и телефон' });
  const a = {
    id: 'a' + Date.now() + crypto.randomBytes(3).toString('hex'),
    date: new Date().toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' }),
    owner,
    bio: { front: !!(b.bio||{}).front, left: !!(b.bio||{}).left, right: !!(b.bio||{}).right },
    photos: {},
    matchScore: Math.max(0, Math.min(100, Number(b.matchScore) || 0)),
    status: 'pending', reason: ''
  };
  // Фото: только небольшие JPEG (data URL)
  const okPhoto = v => typeof v === 'string' && v.length < 200000 && /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(v);
  ['front', 'left', 'right'].forEach(k => { const v = (b.photos || {})[k]; if (okPhoto(v)) a.photos[k] = v; });
  a.bio = { front: !!a.photos.front, left: !!a.photos.left, right: !!a.photos.right };
  db.applications.unshift(a); save();
  res.json({ ok: true, id: a.id });
});

// список без фото (они тяжёлые), фото отдаются отдельным запросом
app.get('/api/applications', auth, (req, res) =>
  res.json(db.applications.map(a => { const { photos, ...rest } = a; return { ...rest, hasPhotos: !!(photos && photos.front) }; })));

app.get('/api/applications/:id/photos', auth, (req, res) => {
  const a = db.applications.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Заявка не найдена' });
  res.set('Cache-Control', 'no-store');
  res.json(a.photos || {});
});

app.post('/api/applications/:id/decision', auth, (req, res) => {
  const a = db.applications.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Заявка не найдена' });
  if (a.status !== 'pending') return res.status(409).json({ error: 'Решение уже принято' });
  const status = req.body.status;
  const reason = clip(req.body.reason, 500).trim();
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Неверный статус' });
  if (status === 'rejected' && !reason) return res.status(400).json({ error: 'Укажите причину отклонения' });
  a.status = status; a.reason = status === 'rejected' ? reason : ''; a.decidedAt = Date.now();
  save();
  res.json({ ok: true });
});

// Статус для заявителя (по телефону, без личных данных)
app.get('/api/status', (req, res) => {
  if (!limit('st:' + req.ip, 30, 600e3)) return res.status(429).json({ error: 'Слишком много запросов' });
  const ph = digits(req.query.phone);
  if (ph.length < 10) return res.status(400).json({ error: 'Введите телефон полностью' });
  res.json(db.applications.filter(a => digits(a.owner.phone) === ph)
    .map(a => ({ id: a.id, date: a.date, dogName: a.owner.dogName, status: a.status, reason: a.reason })));
});

// ===== Собаки =====
app.get('/api/dogs', (req, res) => res.json(db.dogs));
app.put('/api/dogs', auth, (req, res) => {
  if (!Array.isArray(req.body) || req.body.length > 200) return res.status(400).json({ error: 'Неверные данные' });
  db.dogs = req.body; save(); res.json({ ok: true });
});

if (fs.existsSync(path.join(__dirname, 'public'))) app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.send('PoodleHelp API работает'));
app.listen(PORT, () => console.log(`PoodleHelp: http://localhost:${PORT}`));
