# Secure Login App

A small, beginner-friendly login system built with Node.js, Express, and SQLite.
It demonstrates the core building blocks of a secure authentication flow —
each one kept intentionally simple so you can read every line and understand
exactly what it's doing.

## Features

- **User registration and login** with passwords hashed using **bcrypt** (never stored in plain text)
- **Input validation** on the server (username format, email format, password strength) using `express-validator`
- **SQL injection protection** via parameterized queries (`better-sqlite3` with `?` placeholders — user input is never concatenated into SQL)
- **Session-based authentication** with `express-session`, including:
  - Session regeneration on login (prevents session fixation)
  - `httpOnly` cookies (JavaScript can't read them)
  - A working **logout** that destroys the session
- **Account lockout** after 5 failed login attempts (15-minute cooldown) to slow down brute-force guessing
- **Optional Two-Factor Authentication (2FA)** using TOTP (compatible with Google Authenticator, Authy, etc.), via `speakeasy` + a QR code from `qrcode`

## Project structure

```
secure-login-app/
├── server.js           # App entry point, session config
├── db.js                # SQLite connection + schema
├── middleware/
│   └── auth.js           # requireAuth guard for protected routes
├── routes/
│   └── auth.js           # register, login, 2FA, logout routes
├── views/                # EJS templates (auto-escaped, so no XSS from user input)
├── public/
│   └── style.css
├── .env.example
└── package.json
```

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create your `.env` file from the example, and set a real secret:
   ```bash
   cp .env.example .env
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   # paste the output as SESSION_SECRET in .env
   ```

3. Start the app:
   ```bash
   npm start
   ```

4. Open **http://localhost:3000** and register an account.

The SQLite database file (`users.db`) is created automatically on first run —
no separate database server needed.

## Trying out 2FA

1. Log in, then go to **"Set up 2FA"** on the dashboard.
2. Scan the QR code with an authenticator app.
3. Enter the 6-digit code it shows you to confirm and enable 2FA.
4. Log out and log back in — you'll now be asked for a code after your password.

## Security notes (things to know before going further)

This app covers the fundamentals well, but a few things are simplified for
learning purposes. Before using something like this for real users:

- **Use HTTPS in production**, and set `NODE_ENV=production` so cookies are
  marked `secure` (browser will only send them over HTTPS).
- **Swap the session store.** This app uses Express's default in-memory
  session store, which is fine for learning but resets on every restart and
  doesn't scale past one server process. For production, use something like
  `connect-sqlite3` or `connect-redis`.
- **Add rate limiting** (e.g. `express-rate-limit`) at the network level, in
  addition to the account lockout already included, to slow down automated
  attacks across many accounts.
- **Add CSRF protection** for extra defense-in-depth on top of the `sameSite:
  'lax'` cookie setting already in place, especially if you add more
  state-changing forms.
- **Add email verification** and a password-reset flow — both were left out
  here to keep the example focused.
- **Consider `helmet`** for sensible default HTTP security headers.

## Why each piece matters

| Feature | Protects against |
|---|---|
| bcrypt password hashing | Passwords being readable if the database leaks |
| Parameterized SQL queries | SQL injection |
| Input validation | Malformed data, weak passwords, bad emails |
| `httpOnly` + `sameSite` cookies | Cookie theft via XSS, basic CSRF |
| Session regeneration on login | Session fixation attacks |
| Generic "invalid username or password" error | Attackers learning which usernames exist |
| Account lockout | Brute-force password guessing |
| 2FA (TOTP) | Account takeover even if the password is stolen |
