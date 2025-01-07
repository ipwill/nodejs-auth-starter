// server.js
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import speakeasy from 'speakeasy';
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
import qrcode from 'qrcode';

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

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : [];

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

const allowedHosts = process.env.ALLOWED_HOSTS
  ? process.env.ALLOWED_HOSTS.split(',').map(host => host.trim())
  : ['localhost:3000'];

app.use((req, res, next) => {
  const host = req.headers.host;
  if (!allowedHosts.includes(host)) {
    return res.status(400).send('Invalid Host Header');
  }
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
      totp_secret TEXT,
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
  `);
}
initializeDatabase();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: true,
  },
});

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

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.cookies.authToken) {
    token = req.cookies.authToken;
  }

  if (token) {
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Unauthorized: Invalid or expired token.' });
    }
    const user = db.prepare('SELECT current_token FROM users WHERE id = ?').get(decoded.userId);
    if (!user || user.current_token !== token) {
      return res.status(401).json({ message: 'Unauthorized: Invalid or expired token.' });
    }
    req.user = decoded;
    next();
  } else {
    return res.status(401).json({ message: 'Unauthorized: No token provided.' });
  }
}

const tokens = new csrf();
const csrfProtection = (req, res, next) => {
  if (req.method === 'GET') {
    const secret = tokens.secretSync();
    res.cookie('csrfSecret', secret, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict' });
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

app.get('/', csrfProtection, (req, res) => {
  res.render('index', { title: 'Login App', csrfToken: res.locals.csrfToken });
});

app.post(
  '/api/register',
  csrfProtection,
  [
    body('username').notEmpty(),
    body('email').isEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/[a-z]/)
      .matches(/[A-Z]/)
      .matches(/[0-9]/)
      .matches(/[@$!%*?&]/),
    body('twoFactorMethod').optional().isIn(['email', 'totp']),
    body('bypass2FA').optional().isBoolean(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const sanitizedErrors = errors.array().map(err => ({ field: err.param, message: err.msg }));
      return res.status(400).json({ message: 'Validation failed.', errors: sanitizedErrors });
    }
    try {
      const { username, email, password, twoFactorMethod, bypass2FA } = req.body;
      const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
      if (existingUser) {
        return res.status(400).json({ message: 'Username or email is already taken.' });
      }
      const hashedPassword = await bcrypt.hash(password, 12);
      const timestamp = Date.now();
      const dashboardToken = crypto.randomBytes(32).toString('hex');
      const insertStmt = db.prepare(`
        INSERT INTO users (username, email, password, two_factor_method, bypass_2fa, dashboard_token, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const result = insertStmt.run(username, email, hashedPassword, twoFactorMethod || null, bypass2FA ? 1 : 0, dashboardToken, timestamp, timestamp);
      const userId = result.lastInsertRowid;
      let totpSecret = null;
      let qrCodeDataURL = null;
      if (twoFactorMethod === 'totp' && !bypass2FA) {
        const secret = speakeasy.generateSecret({ name: `App (${username})` });
        totpSecret = encrypt(secret.base32);
        db.prepare('UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?').run(
          totpSecret,
          Date.now(),
          userId
        );
        qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);
      }
      const token = generateToken(userId, username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?').run(
        token,
        Date.now(),
        userId
      );
      res.cookie('authToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict' });
      return res.status(201).json({
        message: 'Registration successful.',
        twoFactorMethod,
        dashboardToken,
        qrCode: qrCodeDataURL,
      });
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
    body('bypass2FA').optional().isBoolean(),
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
      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials.' });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid credentials.' });
      }
      if (user.two_factor_method && !user.bypass_2fa && !bypass2FA) {
        if (user.two_factor_method === 'email') {
          const code = Math.floor(100000 + Math.random() * 900000).toString();
          const expires = Date.now() + 10 * 60 * 1000;
          await transporter.sendMail({
            from: process.env.SMTP_USER,
            to: user.email,
            subject: 'Your 2FA Verification Code',
            text: `Your verification code is: ${code}. It expires in 10 minutes.`,
          });
          db.prepare(
            'UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?'
          ).run(code, expires, Date.now(), user.id);
        }
        return res.json({ twoFactorRequired: true, twoFactorMethod: user.two_factor_method });
      }
      const token = generateToken(user.id, username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?').run(
        token,
        Date.now(),
        user.id
      );
      res.cookie('authToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict' });
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
    body('token')
      .isLength({ min: 6, max: 6 })
      .isNumeric(),
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
      if (!user) {
        return res.status(400).json({ message: 'Invalid user.' });
      }
      let is2FAValid = false;
      if (user.two_factor_method === 'totp') {
        const decryptedSecret = decrypt(user.totp_secret);
        is2FAValid = speakeasy.totp.verify({
          secret: decryptedSecret,
          encoding: 'base32',
          token,
          window: 1,
        });
      } else if (user.two_factor_method === 'email') {
        if (user.email_code === token && user.email_code_expires > Date.now()) {
          is2FAValid = true;
          db.prepare('UPDATE users SET email_code = NULL, email_code_expires = NULL, updated_at = ? WHERE id = ?').run(
            Date.now(),
            user.id
          );
        }
      }
      if (!is2FAValid) {
        return res.status(400).json({ message: 'Invalid or expired 2FA token.' });
      }
      const authToken = generateToken(user.id, username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?').run(
        authToken,
        Date.now(),
        user.id
      );
      res.cookie('authToken', authToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict' });
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
    db.prepare('UPDATE users SET current_token = NULL, updated_at = ? WHERE id = ?').run(
      Date.now(),
      userId
    );
    res.clearCookie('authToken');
    return res.json({ message: 'Logged out successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Logout failed due to a server error.' });
  }
});

app.get('/user/:dashboardToken', authenticateToken, csrfProtection, (req, res) => {
  const user = db.prepare('SELECT username FROM users WHERE dashboard_token = ? AND id = ?').get(req.params.dashboardToken, req.user.userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found or invalid dashboard token.' });
  }
  res.render('user-dashboard', { username: user.username, csrfToken: res.locals.csrfToken });
});

app.use('/favicon.ico', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.all('*', (req, res) => {
  res.status(404).json({ message: 'Endpoint not found.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});