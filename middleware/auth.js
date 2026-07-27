// middleware/auth.js
// Simple guard: if there's no logged-in user on the session, send them to /login.

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

module.exports = { requireAuth };
