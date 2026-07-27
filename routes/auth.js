// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const SALT_ROUNDS = 12;          // bcrypt cost factor - higher = slower to crack, slower to run
const MAX_FAILED_ATTEMPTS = 5;   // lock the account after this many wrong passwords
const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes

/* ---------------------------------------------------------
   REGISTER
--------------------------------------------------------- */

router.get('/register', (req, res) => {
  res.render('register', { errors: [], old: {} });
});

router.post(
  '/register',
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters')
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores'),
    body('email')
      .trim()
      .isEmail().withMessage('Please enter a valid email address')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/).withMessage('Password must include an uppercase letter')
      .matches(/[a-z]/).withMessage('Password must include a lowercase letter')
      .matches(/[0-9]/).withMessage('Password must include a number'),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('register', {
        errors: errors.array().map((e) => e.msg),
        old: { username: req.body.username, email: req.body.email }
      });
    }

    const { username, email, password } = req.body;

    try {
      // Parameterized query - user input is never concatenated into SQL text,
      // so it can't be used to inject SQL commands.
      const existing = db
        .prepare('SELECT id FROM users WHERE username = ? OR email = ?')
        .get(username, email);

      if (existing) {
        return res.render('register', {
          errors: ['That username or email is already registered'],
          old: { username, email }
        });
      }

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      db.prepare(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
      ).run(username, email, passwordHash);

      res.redirect('/login?registered=1');
    } catch (err) {
      console.error('Registration error:', err);
      res.render('register', {
        errors: ['Something went wrong. Please try again.'],
        old: { username, email }
      });
    }
  }
);

/* ---------------------------------------------------------
   LOGIN
--------------------------------------------------------- */

router.get('/login', (req, res) => {
  res.render('login', { error: null, registered: req.query.registered === '1' });
});

router.post(
  '/login',
  [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('login', { error: 'Please enter both username and password', registered: false });
    }

    const { username, password } = req.body;
    const genericError = 'Invalid username or password'; // never reveal *which* was wrong

    try {
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

      if (!user) {
        return res.render('login', { error: genericError, registered: false });
      }

      if (user.locked_until && user.locked_until > Date.now()) {
        const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
        return res.render('login', {
          error: `Too many failed attempts. Try again in ${minutesLeft} minute(s).`,
          registered: false
        });
      }

      const passwordMatches = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatches) {
        const attempts = user.failed_attempts + 1;
        const lockedUntil = attempts >= MAX_FAILED_ATTEMPTS ? Date.now() + LOCK_TIME_MS : null;

        db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
          .run(attempts, lockedUntil, user.id);

        return res.render('login', { error: genericError, registered: false });
      }

      // Correct password - reset the failed-attempt counter
      db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);

      if (user.twofa_enabled) {
        // Password is right, but don't fully log in yet - 2FA code still needed
        req.session.pending2FAUserId = user.id;
        return res.redirect('/login/2fa');
      }

      // Regenerate the session on login to prevent session fixation attacks
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regenerate error:', err);
          return res.render('login', { error: 'Something went wrong. Please try again.', registered: false });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/dashboard');
      });
    } catch (err) {
      console.error('Login error:', err);
      res.render('login', { error: 'Something went wrong. Please try again.', registered: false });
    }
  }
);

/* ---------------------------------------------------------
   2FA - LOGIN-TIME VERIFICATION
--------------------------------------------------------- */

router.get('/login/2fa', (req, res) => {
  if (!req.session.pending2FAUserId) return res.redirect('/login');
  res.render('login-2fa', { error: null });
});

router.post('/login/2fa', (req, res) => {
  if (!req.session.pending2FAUserId) return res.redirect('/login');

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.pending2FAUserId);
  const { token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: user.twofa_secret,
    encoding: 'base32',
    token,
    window: 1 // allows the code from 30s before/after for clock drift
  });

  if (!verified) {
    return res.render('login-2fa', { error: 'Invalid authentication code' });
  }

  const userId = user.id;
  delete req.session.pending2FAUserId;

  req.session.regenerate((err) => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.render('login-2fa', { error: 'Something went wrong. Please try again.' });
    }
    req.session.userId = userId;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

/* ---------------------------------------------------------
   2FA - SETUP (requires being logged in)
--------------------------------------------------------- */

router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

  if (user.twofa_enabled) {
    return res.render('2fa-setup', { alreadyEnabled: true, qrCode: null, error: null });
  }

  const secret = speakeasy.generateSecret({ name: `SecureLoginApp (${user.username})` });
  db.prepare('UPDATE users SET twofa_secret = ? WHERE id = ?').run(secret.base32, user.id);

  const qrCode = await qrcode.toDataURL(secret.otpauth_url);
  res.render('2fa-setup', { alreadyEnabled: false, qrCode, error: null });
});

router.post('/2fa/setup', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const { token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: user.twofa_secret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    return res.render('2fa-setup', {
      alreadyEnabled: false,
      qrCode: null,
      error: 'That code was not accepted. Scan the QR code again and try once more.'
    });
  }

  db.prepare('UPDATE users SET twofa_enabled = 1 WHERE id = ?').run(user.id);
  res.redirect('/dashboard');
});

router.post('/2fa/disable', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?').run(req.session.userId);
  res.redirect('/dashboard');
});

/* ---------------------------------------------------------
   LOGOUT
--------------------------------------------------------- */

router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;
