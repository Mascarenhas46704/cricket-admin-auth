// server.js
require('dotenv').config();
const express        = require('express');
const path           = require('path');              // ← only one 'path' import
const session        = require('express-session');
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const speakeasy      = require('speakeasy');
const QRCode         = require('qrcode');

// 1. Initialize Express
const app = express();

// 2. Serve static assets (css, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// 3. Views configuration
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// 4. Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret:           process.env.SESSION_SECRET,
  resave:           false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// 5. Passport Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, { id: profile.id, displayName: profile.displayName });
  }
));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// 6. In-memory 2FA store (demo only)
const twoFactorSecrets = {};

// 7. Two-Step (TOTP) Authentication Routes
app.get('/2fa/setup', ensureAuthenticated, (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20 });
  twoFactorSecrets[req.user.id] = secret.base32;
  QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
    res.render('twofactor', { qr: data_url });
  });
});

app.post('/2fa/verify', ensureAuthenticated, (req, res) => {
  const userSecret = twoFactorSecrets[req.user.id];
  const { token } = req.body;
  const verified = speakeasy.totp.verify({
    secret:   userSecret,
    encoding: 'base32',
    token,
    window:   1
  });
  if (verified) return res.redirect('/dashboard');
  res.redirect('/2fa/setup');
});

// 8. Auth & Dashboard Routes
app.get('/', (req, res) => res.render('login'));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/2fa/setup')
);

app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { admin: req.user.displayName });
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// 9. Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);

// Helper to protect routes
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
}
