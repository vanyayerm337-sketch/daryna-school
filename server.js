/**
 * Daryna English School — Backend Server
 * Production-ready Express.js REST API
 * Author: Senior Dev Build
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Security headers
app.use((req, res, next) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  next();
});

// Request logging
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.path}`);
  next();
});

// ─── In-Memory Database (swap for SQLite/PostgreSQL in production) ──────────
const db = {
  users: [
    { id: 1, name: 'Дарина Коваль', email: 'admin@school.com', passwordHash: hashPass('admin123'), role: 'admin', avatar: 'ДК', createdAt: '2024-09-01' },
    { id: 2, name: 'Максим Іваненко', email: 'student@school.com', passwordHash: hashPass('student123'), role: 'student', avatar: 'МІ', level: 'B1 Pre-Intermediate', phone: '+38050111222', balance: 3, createdAt: '2025-01-15' },
  ],
  sessions: new Map(), // token → userId
  lessons: [],
  schedules: [],
  homework: [],
  payments: [],
  resources: [],
  videos: [],
  onlineLinks: [],
  invites: [],
  nextId: { user: 3, lesson: 1, schedule: 1, homework: 1, payment: 1, resource: 1, video: 1, link: 1 }
};

function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + 'daryna-salt-2024').digest('hex');
}

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── Auth Middleware ─────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !db.sessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = db.sessions.get(token);
  req.user = db.users.find(u => u.id === req.userId);
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
  });
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || user.passwordHash !== hashPass(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = makeToken();
  db.sessions.set(token, user.id);

  // Clean sensitive data
  const { passwordHash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already in use' });

  const user = {
    id: db.nextId.user++,
    name, email,
    passwordHash: hashPass(password),
    role: 'student',
    avatar: name.split(' ').map(n => n[0]).join('').slice(0,2).toUpperCase(),
    level: 'Beginner (A1)',
    phone: '',
    balance: 0,
    createdAt: new Date().toISOString().slice(0,10)
  };
  db.users.push(user);

  const token = makeToken();
  db.sessions.set(token, user.id);
  const { passwordHash, ...safeUser } = user;
  res.status(201).json({ token, user: safeUser });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  db.sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const { passwordHash, ...safeUser } = req.user;
  res.json(safeUser);
});

// ─── USERS / STUDENTS ─────────────────────────────────────────────────────────
app.get('/api/students', requireAuth, (req, res) => {
  const stds = db.users.filter(u => u.role === 'student').map(({ passwordHash, ...u }) => u);
  res.json(stds);
});

app.post('/api/students', requireAdmin, (req, res) => {
  const { name, email, level, phone } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email exists' });

  const student = {
    id: db.nextId.user++, name, email,
    passwordHash: hashPass(Math.random().toString(36).slice(2)),
    role: 'student',
    avatar: name.split(' ').map(n => n[0]).join('').slice(0,2).toUpperCase(),
    level: level || 'Beginner (A1)',
    phone: phone || '', balance: 0,
    createdAt: new Date().toISOString().slice(0,10)
  };
  db.users.push(student);
  const { passwordHash, ...safeStudent } = student;
  res.status(201).json(safeStudent);
});

app.get('/api/students/:id', requireAuth, (req, res) => {
  const student = db.users.find(u => u.id === parseInt(req.params.id) && u.role === 'student');
  if (!student) return res.status(404).json({ error: 'Not found' });
  const { passwordHash, ...safe } = student;
  res.json(safe);
});

app.put('/api/students/:id', requireAdmin, (req, res) => {
  const student = db.users.find(u => u.id === parseInt(req.params.id) && u.role === 'student');
  if (!student) return res.status(404).json({ error: 'Not found' });
  const { name, level, phone } = req.body;
  if (name) student.name = name;
  if (level) student.level = level;
  if (phone !== undefined) student.phone = phone;
  const { passwordHash, ...safe } = student;
  res.json(safe);
});

app.delete('/api/students/:id', requireAdmin, (req, res) => {
  const idx = db.users.findIndex(u => u.id === parseInt(req.params.id) && u.role === 'student');
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.users.splice(idx, 1);
  res.json({ ok: true });
});

app.post('/api/students/invite', requireAdmin, (req, res) => {
  const { email, message } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const invite = { id: Date.now(), email, message, sentAt: new Date().toISOString(), status: 'sent' };
  db.invites.push(invite);
  // In production: send actual email via SendGrid/Resend
  console.log(`[INVITE] Sending invite to: ${email}`);
  res.json({ ok: true, invite });
});

// ─── PROFILE ─────────────────────────────────────────────────────────────────
app.put('/api/profile', requireAuth, (req, res) => {
  const { name, phone } = req.body;
  if (name) req.user.name = name;
  if (phone !== undefined) req.user.phone = phone;
  const { passwordHash, ...safe } = req.user;
  res.json(safe);
});

app.put('/api/profile/password', requireAuth, (req, res) => {
  const { current, newPassword } = req.body;
  if (req.user.passwordHash !== hashPass(current)) return res.status(400).json({ error: 'Wrong current password' });
  req.user.passwordHash = hashPass(newPassword);
  res.json({ ok: true });
});

// ─── LESSONS / MATERIALS ─────────────────────────────────────────────────────
app.get('/api/lessons', requireAuth, (req, res) => {
  const { type, level } = req.query;
  let lessons = db.lessons;
  if (type) lessons = lessons.filter(l => l.type === type);
  if (level) lessons = lessons.filter(l => l.level === level);
  res.json(lessons);
});

app.post('/api/lessons', requireAdmin, (req, res) => {
  const { title, type, description, url, level } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const lesson = {
    id: db.nextId.lesson++, title, type: type || 'lesson',
    description: description || '', url: url || '', level: level || 'All',
    createdBy: req.userId, createdAt: new Date().toISOString()
  };
  db.lessons.push(lesson);
  res.status(201).json(lesson);
});

app.delete('/api/lessons/:id', requireAdmin, (req, res) => {
  const idx = db.lessons.findIndex(l => l.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.lessons.splice(idx, 1);
  res.json({ ok: true });
});

// ─── SCHEDULE / CALENDAR ─────────────────────────────────────────────────────
app.get('/api/schedules', requireAuth, (req, res) => {
  const { studentId, date, month } = req.query;
  let schedules = db.schedules;

  if (req.user.role === 'student') {
    schedules = schedules.filter(s => s.studentId === req.userId);
  } else if (studentId) {
    schedules = schedules.filter(s => s.studentId === parseInt(studentId));
  }
  if (date) schedules = schedules.filter(s => s.date === date);
  if (month) schedules = schedules.filter(s => s.date.startsWith(month));

  res.json(schedules);
});

app.post('/api/schedules', requireAdmin, (req, res) => {
  const { studentId, date, time, type } = req.body;
  if (!studentId || !date || !time) return res.status(400).json({ error: 'studentId, date, time required' });

  const schedule = {
    id: db.nextId.schedule++,
    studentId: parseInt(studentId),
    date, time, type: type || 'Individual',
    status: 'planned',
    createdAt: new Date().toISOString()
  };
  db.schedules.push(schedule);
  res.status(201).json(schedule);
});

app.patch('/api/schedules/:id/status', requireAdmin, (req, res) => {
  const schedule = db.schedules.find(s => s.id === parseInt(req.params.id));
  if (!schedule) return res.status(404).json({ error: 'Not found' });
  const { status } = req.body;
  if (!['planned','completed','missed'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  schedule.status = status;
  schedule.updatedAt = new Date().toISOString();

  // Deduct lesson from balance if completed
  if (status === 'completed') {
    const student = db.users.find(u => u.id === schedule.studentId);
    if (student && student.balance > 0) student.balance--;
  }
  res.json(schedule);
});

app.delete('/api/schedules/:id', requireAdmin, (req, res) => {
  const idx = db.schedules.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.schedules.splice(idx, 1);
  res.json({ ok: true });
});

// ─── HOMEWORK ─────────────────────────────────────────────────────────────────
app.get('/api/homework', requireAuth, (req, res) => {
  let hw = db.homework;
  if (req.user.role === 'student') hw = hw.filter(h => h.studentId === req.userId);
  const { status } = req.query;
  if (status) hw = hw.filter(h => h.status === status);
  res.json(hw);
});

app.post('/api/homework', requireAdmin, (req, res) => {
  const { studentId, title, description, deadline } = req.body;
  if (!studentId || !title) return res.status(400).json({ error: 'studentId and title required' });
  const hw = {
    id: db.nextId.homework++,
    studentId: parseInt(studentId),
    title, description: description || '',
    deadline: deadline || null,
    status: 'pending',
    answer: '', grade: null, comment: '',
    createdAt: new Date().toISOString()
  };
  db.homework.push(hw);
  res.status(201).json(hw);
});

app.patch('/api/homework/:id/submit', requireAuth, (req, res) => {
  const hw = db.homework.find(h => h.id === parseInt(req.params.id));
  if (!hw) return res.status(404).json({ error: 'Not found' });
  if (req.user.role === 'student' && hw.studentId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const { answer } = req.body;
  if (!answer) return res.status(400).json({ error: 'Answer required' });
  hw.answer = answer;
  hw.status = 'submitted';
  hw.submittedAt = new Date().toISOString();
  res.json(hw);
});

app.patch('/api/homework/:id/grade', requireAdmin, (req, res) => {
  const hw = db.homework.find(h => h.id === parseInt(req.params.id));
  if (!hw) return res.status(404).json({ error: 'Not found' });
  const { grade, comment } = req.body;
  if (!grade || grade < 1 || grade > 12) return res.status(400).json({ error: 'Grade 1-12 required' });
  hw.grade = parseInt(grade);
  hw.comment = comment || '';
  hw.status = 'graded';
  hw.gradedAt = new Date().toISOString();
  res.json(hw);
});

app.delete('/api/homework/:id', requireAdmin, (req, res) => {
  const idx = db.homework.findIndex(h => h.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.homework.splice(idx, 1);
  res.json({ ok: true });
});

// ─── PAYMENTS ─────────────────────────────────────────────────────────────────
const LESSON_PRICE = 400; // UAH

app.get('/api/payments', requireAuth, (req, res) => {
  let payments = db.payments;
  if (req.user.role === 'student') payments = payments.filter(p => p.studentId === req.userId);
  res.json(payments);
});

app.post('/api/payments', requireAdmin, (req, res) => {
  const { studentId, lessons } = req.body;
  if (!studentId || !lessons) return res.status(400).json({ error: 'studentId and lessons required' });
  const count = parseInt(lessons);
  const amount = count * LESSON_PRICE;

  const student = db.users.find(u => u.id === parseInt(studentId));
  if (!student) return res.status(404).json({ error: 'Student not found' });

  student.balance += count;

  const payment = {
    id: db.nextId.payment++,
    studentId: parseInt(studentId),
    lessons: count, amount,
    status: 'paid',
    date: new Date().toISOString().slice(0,10),
    createdAt: new Date().toISOString()
  };
  db.payments.push(payment);
  res.status(201).json({ payment, newBalance: student.balance });
});

app.get('/api/payments/stats', requireAdmin, (req, res) => {
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
  const monthPayments = db.payments.filter(p => p.date.startsWith(thisMonth));
  res.json({
    totalRevenue: db.payments.reduce((s,p) => s+p.amount, 0),
    monthRevenue: monthPayments.reduce((s,p) => s+p.amount, 0),
    monthLessons: monthPayments.reduce((s,p) => s+p.lessons, 0),
    totalPayments: db.payments.length,
  });
});

// ─── RESOURCES / LIBRARY ─────────────────────────────────────────────────────
app.get('/api/resources', requireAuth, (req, res) => res.json(db.resources));
app.post('/api/resources', requireAdmin, (req, res) => {
  const { title, type, description, url } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const resource = {
    id: db.nextId.resource++, title, type: type || 'file',
    description: description || '', url: url || '',
    createdAt: new Date().toISOString()
  };
  db.resources.push(resource);
  res.status(201).json(resource);
});
app.delete('/api/resources/:id', requireAdmin, (req, res) => {
  const idx = db.resources.findIndex(r => r.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.resources.splice(idx, 1);
  res.json({ ok: true });
});

// ─── VIDEOS ──────────────────────────────────────────────────────────────────
app.get('/api/videos', requireAuth, (req, res) => res.json(db.videos));
app.post('/api/videos', requireAdmin, (req, res) => {
  const { title, url, description } = req.body;
  if (!title || !url) return res.status(400).json({ error: 'Title and URL required' });
  const video = { id: db.nextId.video++, title, url, description: description || '', createdAt: new Date().toISOString() };
  db.videos.push(video);
  res.status(201).json(video);
});
app.delete('/api/videos/:id', requireAdmin, (req, res) => {
  const idx = db.videos.findIndex(v => v.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.videos.splice(idx, 1);
  res.json({ ok: true });
});

// ─── ONLINE LINKS ─────────────────────────────────────────────────────────────
app.get('/api/online-links', requireAuth, (req, res) => res.json(db.onlineLinks));
app.post('/api/online-links', requireAdmin, (req, res) => {
  const { platform, name, url } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL required' });
  const link = { id: db.nextId.link++, platform: platform || 'Zoom', name, url, createdAt: new Date().toISOString() };
  db.onlineLinks.push(link);
  res.status(201).json(link);
});
app.delete('/api/online-links/:id', requireAdmin, (req, res) => {
  const idx = db.onlineLinks.findIndex(l => l.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.onlineLinks.splice(idx, 1);
  res.json({ ok: true });
});

// ─── SETTINGS ─────────────────────────────────────────────────────────────────
let schoolSettings = { lessonPrice: 400, lessonDurationMin: 60, schoolName: "Daryna English School" };
app.get('/api/settings', requireAdmin, (req, res) => res.json(schoolSettings));
app.put('/api/settings', requireAdmin, (req, res) => {
  const { lessonPrice, lessonDurationMin, schoolName } = req.body;
  if (lessonPrice) schoolSettings.lessonPrice = parseInt(lessonPrice);
  if (lessonDurationMin) schoolSettings.lessonDurationMin = parseInt(lessonDurationMin);
  if (schoolName) schoolSettings.schoolName = schoolName;
  res.json(schoolSettings);
});

// ─── CATCH-ALL: serve index.html for SPA ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🌐 Daryna English School API running at http://localhost:${PORT}`);
  console.log(`📚 API docs: http://localhost:${PORT}/api`);
  console.log(`\n👤 Admin:   admin@school.com / admin123`);
  console.log(`👨‍🎓 Student: student@school.com / student123\n`);
});

module.exports = app;
