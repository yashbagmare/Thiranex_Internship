// server.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');

const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set in .env - using an insecure default. Set this before deploying.');
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'insecure-default-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,          // JavaScript on the page can't read the cookie
      sameSite: 'lax',         // basic CSRF mitigation
      secure: process.env.NODE_ENV === 'production', // cookie only sent over HTTPS in production
      maxAge: 1000 * 60 * 60 * 2 // 2 hours
    }
    // NOTE: the default MemoryStore used here is fine for learning/local dev only.
    // For production, use a persistent store (e.g. connect-sqlite3, connect-redis).
  })
);

app.use('/', authRoutes);

app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/dashboard' : '/login');
});

app.get('/dashboard', requireAuth, (req, res) => {
  const db = require('./db');
  const user = db.prepare('SELECT twofa_enabled FROM users WHERE id = ?').get(req.session.userId);
  res.render('dashboard', {
    username: req.session.username,
    twofaEnabled: !!user.twofa_enabled
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Secure login app running at http://localhost:${PORT}`);
});
