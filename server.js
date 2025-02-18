import express from 'express';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';
import csrf from 'csrf';
import cookieParser from 'cookie-parser';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const db = new Database(process.env.DB_PATH || 'database.db');

app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        connectSrc: ["'self'"],
        upgradeInsecureRequests: [],
    },
  })
);

if (process.env.NODE_ENV === 'production') {
  app.enable('trust proxy');
  app.use((req, res, next) => {
    if (req.secure) {
      next();
    } else {
      res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
  });
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});
app.use('/api/', apiLimiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : [];
app.use(
  cors({
    origin: process.env.NODE_ENV === 'development' ? '*' : allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-CSRF-Token'],
    credentials: true,
  })
);

app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: process.env.NODE_ENV === 'production' ? '1y' : 0,
    etag: false,
  })
);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const allowedHosts = process.env.ALLOWED_HOSTS ? process.env.ALLOWED_HOSTS.split(',').map(host => host.trim()) : ['localhost:3000'];
app.use((req, res, next) => {
  const host = req.headers.host;
  if (!allowedHosts.includes(host)) return res.status(400).send('Invalid Host Header');
  next();
});

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

function initializeDatabase() {
  db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    two_factor_method TEXT,
    email_code TEXT,
    email_code_expires INTEGER,
    password_reset_token TEXT,
    password_reset_expires INTEGER,
    bypass_2fa BOOLEAN DEFAULT 0,
    current_token TEXT,
    dashboard_token TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS user_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    old_username TEXT,
    old_email TEXT,
    old_password TEXT,
    changed_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  `);
}
initializeDatabase();

const transporterConfig = {
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === 'true',
  tls: { rejectUnauthorized: true }
};
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporterConfig.auth = { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS };
}
const transporter = nodemailer.createTransport(transporterConfig);

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV = process.env.ENCRYPTION_IV;
const algorithm = 'aes-256-cbc';
function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(IV, 'hex'));
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
function decrypt(text) {
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(IV, 'hex'));
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
function generateToken(userId, username) {
  return jwt.sign({ userId, username }, process.env.JWT_SECRET, { expiresIn: '24h' });
}
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax'
};

function authenticateToken(req, res, next) {
  const token = req.cookies.authToken || (req.headers.authorization ? req.headers.authorization.split(' ')[1] : null);
  if (!token) return res.redirect('/logged-out?reason=noToken');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = db.prepare('SELECT current_token FROM users WHERE id = ?').get(decoded.userId);
    if (!user || !user.current_token || user.current_token !== token) {
      res.clearCookie('authToken', cookieOptions);
      return res.redirect('/logged-out?reason=expired');
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('authToken', cookieOptions);
    return res.redirect('/logged-out?reason=invalidToken');
  }
}

const tokens = new csrf();
const csrfProtection = (req, res, next) => {
  if (req.method === 'GET') {
    const secret = tokens.secretSync();
    res.cookie('csrfSecret', secret, cookieOptions);
    const token = tokens.create(secret);
    res.locals.csrfToken = token;
    next();
  } else {
    const secret = req.cookies.csrfSecret;
    const token = req.headers['x-csrf-token'];
    if (tokens.verify(secret, token)) {
      next();
    } else {
      res.status(403).json({ message: 'Invalid CSRF Token' });
    }
  }
};

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, storedHash) {
  const parts = storedHash.split(':');
  const salt = parts[0];
  const originalHash = parts[1];
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(originalHash, 'hex'));
}

app.get('/', csrfProtection, (req, res) => {
  res.render('index', { title: 'Login App', csrfToken: res.locals.csrfToken });
});

app.get('/api/check-auth', authenticateToken, (req, res) => {
  res.json({ ok: true });
});

app.post(
  '/api/register',
  csrfProtection,
  [
    body('username').notEmpty(),
    body('email').isEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/[A-Z]/)
      .matches(/[a-z]/)
      .matches(/[0-9]/)
      .matches(/[@$!%*?&]/),
    body('bypass2FA').optional().isBoolean()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const sanitizedErrors = errors.array().map(err => ({ field: err.param, message: err.msg }));
      return res.status(400).json({ message: 'Validation failed.', errors: sanitizedErrors });
    }
    try {
      const { username, email, password, bypass2FA } = req.body;
      const twoFactorMethod = 'email';
      const existingUser = db
        .prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)')
        .get(username, email);
      if (existingUser)
        return res.status(400).json({ message: 'Username or email is already taken.' });
      const hashedPassword = hashPassword(password);
      const timestamp = Date.now();
      const dashboardToken = crypto.randomBytes(32).toString('hex');
      const result = db.prepare(
        `INSERT INTO users (username, email, password, two_factor_method, bypass_2fa, dashboard_token, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(username, email, hashedPassword, twoFactorMethod, bypass2FA ? 1 : 0, dashboardToken, timestamp, timestamp);
      const userId = result.lastInsertRowid;
      if (bypass2FA) {
        const token = generateToken(userId, username);
        db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
          .run(token, Date.now(), userId);
        res.cookie('authToken', token, cookieOptions);
        return res.status(201).json({ message: 'Registration successful.', dashboardToken, token });
      } else {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 10 * 60 * 1000;
        await transporter.sendMail({
          from: process.env.SMTP_USER || 'no-reply@example.com',
          to: email,
          subject: 'Your 2FA Verification Code',
          text: `Your verification code is: ${code}. It expires in 10 minutes.`
        });
        db.prepare('UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?')
          .run(code, expires, Date.now(), userId);
        return res.status(201).json({
          message: 'Registration successful. 2FA verification required.',
          twoFactorRequired: true,
          twoFactorMethod: 'email',
          dashboardToken
        });
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Registration failed due to a server error.' });
    }
  }
);

app.post(
  '/api/login',
  csrfProtection,
  [
    body('username').notEmpty(),
    body('password').exists(),
    body('bypass2FA').optional().isBoolean()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const sanitizedErrors = errors.array().map(err => ({ field: err.param, message: err.msg }));
      return res.status(400).json({ message: 'Validation failed.', errors: sanitizedErrors });
    }
    try {
      const { username, password, bypass2FA } = req.body;
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!user)
        return res.status(400).json({ message: 'Invalid credentials.' });
      const isPasswordValid = verifyPassword(password, user.password);
      if (!isPasswordValid)
        return res.status(400).json({ message: 'Invalid credentials.' });
      if (user.two_factor_method === 'email' && !user.bypass_2fa && !bypass2FA) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 10 * 60 * 1000;
        await transporter.sendMail({
          from: process.env.SMTP_USER || 'no-reply@example.com',
          to: user.email,
          subject: 'Your 2FA Verification Code',
          text: `Your verification code is: ${code}. It expires in 10 minutes.`
        });
        db.prepare('UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?')
          .run(code, expires, Date.now(), user.id);
        return res.json({ twoFactorRequired: true, twoFactorMethod: 'email' });
      }
      const token = generateToken(user.id, username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
        .run(token, Date.now(), user.id);
      res.cookie('authToken', token, cookieOptions);
      return res.json({ token, dashboardToken: user.dashboard_token });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Login failed due to a server error.' });
    }
  }
);

app.post(
  '/api/verify-2fa',
  csrfProtection,
  [
    body('username').notEmpty(),
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const sanitizedErrors = errors.array().map(err => ({ field: err.param, message: err.msg }));
      return res.status(400).json({ message: 'Validation failed.', errors: sanitizedErrors });
    }
    try {
      const { username, token } = req.body;
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!user)
        return res.status(400).json({ message: 'Invalid user.' });
      let is2FAValid = false;
      if (user.two_factor_method === 'email') {
        if (user.email_code === token && user.email_code_expires > Date.now()) {
          is2FAValid = true;
          db.prepare('UPDATE users SET email_code = NULL, email_code_expires = NULL, updated_at = ? WHERE id = ?')
            .run(Date.now(), user.id);
        }
      }
      if (!is2FAValid)
        return res.status(400).json({ message: 'Invalid or expired 2FA token.' });
      const authToken = generateToken(user.id, username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
        .run(authToken, Date.now(), user.id);
      res.cookie('authToken', authToken, cookieOptions);
      return res.json({ token: authToken, dashboardToken: user.dashboard_token });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: '2FA verification failed due to a server error.' });
    }
  }
);

app.post('/api/logout', csrfProtection, authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    db.prepare('UPDATE users SET current_token = NULL WHERE id = ?').run(userId);
    res.clearCookie('authToken', cookieOptions);
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Logout failed due to a server error.' });
  }
});

app.post('/api/forgot-password', csrfProtection, [body('email').isEmail()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ message: 'Invalid email address.' });
  const { email } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user)
    return res.status(400).json({ message: 'No account associated with that email.' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 3600000;
  db.prepare('UPDATE users SET password_reset_token = ?, password_reset_expires = ?, updated_at = ? WHERE id = ?')
    .run(token, expires, Date.now(), user.id);
  const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER || 'no-reply@example.com',
      to: email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the link below to reset your password:\n\n${resetUrl}\n\nThis link will expire in 1 hour.`
    });
    return res.json({ message: 'Password reset link sent to your email.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error sending password reset email.' });
  }
});

app.get('/reset-password', csrfProtection, (req, res) => {
  const { token, email } = req.query;
  if (!token || !email)
    return res.status(400).send('Invalid password reset link.');
  res.render('reset-password', { token, email, csrfToken: res.locals.csrfToken });
});

app.post('/api/reset-password', csrfProtection, [
  body('email').isEmail(),
  body('token').notEmpty(),
  body('password').isLength({ min: 8 }),
  body('confirmPassword').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ message: 'Validation failed.' });
  const { email, token, password, confirmPassword } = req.body;
  if (password !== confirmPassword)
    return res.status(400).json({ message: 'Passwords do not match.' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user)
    return res.status(400).json({ message: 'Invalid email.' });
  if (user.password_reset_token !== token || user.password_reset_expires < Date.now())
    return res.status(400).json({ message: 'Invalid or expired reset token.' });
  const hashedPassword = hashPassword(password);
  db.prepare('UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL, updated_at = ? WHERE id = ?')
    .run(hashedPassword, Date.now(), user.id);
  res.json({ message: 'Password reset successful.' });
});

app.post('/api/settings/update', authenticateToken, csrfProtection, [
  body('setting').notEmpty(),
  body('value').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ message: 'Invalid input.' });
  const { setting, value } = req.body;
  const userId = req.user.userId;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user)
    return res.status(404).json({ message: 'User not found.' });
  try {
    if (setting === 'username') {
      const existing = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(value);
      if (existing)
        return res.status(400).json({ message: 'Username is already taken.' });
      db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(user.id, user.username, user.email, user.password, Date.now());
      db.prepare('UPDATE users SET username = ?, updated_at = ? WHERE id = ?')
        .run(value, Date.now(), userId);
      return res.json({ message: 'Username updated successfully.' });
    }
    if (setting === 'email') {
      const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)').get(value);
      if (existing)
        return res.status(400).json({ message: 'Email is already taken.' });
      db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(user.id, user.username, user.email, user.password, Date.now());
      db.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?')
        .run(value, Date.now(), userId);
      return res.json({ message: 'Email updated successfully.' });
    }
    if (setting === 'password') {
      const hashed = hashPassword(value);
      db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(user.id, user.username, user.email, user.password, Date.now());
      db.prepare('UPDATE users SET password = ?, updated_at = ? WHERE id = ?')
        .run(hashed, Date.now(), userId);
      return res.json({ message: 'Password updated successfully.' });
    }
    return res.status(400).json({ message: 'Invalid setting.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Could not update user setting.' });
  }
});

app.get('/user/:dashboardToken', authenticateToken, csrfProtection, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const user = db.prepare('SELECT username, email FROM users WHERE dashboard_token = ? AND id = ?')
    .get(req.params.dashboardToken, req.user.userId);
  if (!user)
    return res.status(404).json({ message: 'User not found or invalid dashboard token.' });
  res.render('user-dashboard', { username: user.username, email: user.email, dashboardToken: req.params.dashboardToken, csrfToken: res.locals.csrfToken });
});

app.get('/dashboard', authenticateToken, csrfProtection, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const user = db.prepare('SELECT username, email, dashboard_token FROM users WHERE id = ?')
    .get(req.user.userId);
  if (!user) return res.redirect('/logged-out?reason=notfound');
  res.render('user-dashboard', { username: user.username, email: user.email, dashboardToken: user.dashboard_token, csrfToken: res.locals.csrfToken });
});

app.get('/logged-out', (req, res) => {
  res.render('logged-out', { reason: req.query.reason });
});

app.use('/favicon.ico', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).render('logged-out', {
      title: '404 Not Found',
      reason: 'The page you are looking for does not exist.'
    });
  } else if (req.accepts('json')) {
    res.status(404).json({ message: 'Endpoint not found.' });
  } else {
    res.status(404).type('txt').send('Endpoint not found.');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});
