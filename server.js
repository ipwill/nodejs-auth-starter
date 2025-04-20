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
      scriptSrcAttr: ["'self'"],
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
  if (!allowedHosts.includes(host)) {
      console.warn(`Blocked request with invalid Host header: ${host}`);
      return res.status(400).send('Invalid Host Header');
  }
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

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_dashboard_token ON users(dashboard_token);
  CREATE INDEX IF NOT EXISTS idx_user_history_user_id ON user_history(user_id);
  CREATE INDEX IF NOT EXISTS idx_user_history_old_username ON user_history(old_username);
  CREATE INDEX IF NOT EXISTS idx_user_history_changed_at ON user_history(changed_at);
  `);
  console.log("Database initialized successfully.");
}
initializeDatabase();

let transporter;
if (process.env.NODE_ENV === 'development') {
  console.log('Setting up MailHog transport for development');
  transporter = nodemailer.createTransport({
    host: process.env.MAILHOG_HOST || 'localhost',
    port: parseInt(process.env.MAILHOG_PORT || '1025', 10),
    secure: false,
    ignoreTLS: true
  });
  transporter.verify((error) => {
    if (error) {
      console.log('MailHog not available or connection failed, using mock email transport instead.');
      transporter = {
        sendMail: async (mailOptions) => {
          console.log('\n========== MOCK EMAIL SENT ==========');
          console.log(`To: ${mailOptions.to}`);
          console.log(`From: ${mailOptions.from}`);
          console.log(`Subject: ${mailOptions.subject}`);
          console.log(`Body (Text): ${mailOptions.text}`);
          console.log('======================================\n');
          return { messageId: 'mock-email-id-' + Date.now() };
        }
      };
    } else {
      console.log('MailHog connection successful.');
    }
  });
} else {
  const transporterConfig = {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_SECURE === 'true',
    tls: { rejectUnauthorized: true }
  };
  if (process.env.SMTP_USER && process.env.SMTP_PASS) {
    transporterConfig.auth = { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS };
  }
  try {
    transporter = nodemailer.createTransport(transporterConfig);
    console.log('SMTP transport configured for production.');
  } catch (err) {
    console.error('Failed to create production email transport:', err);
    transporter = {
      sendMail: async (mailOptions) => {
        console.log('\n========== FALLBACK MOCK EMAIL (PROD SETUP FAILED) ==========');
        console.log(`To: ${mailOptions.to}`);
        console.log(`From: ${mailOptions.from}`);
        console.log(`Subject: ${mailOptions.subject}`);
        console.log(`Body (Text): ${mailOptions.text}`);
        console.log('==============================================================\n');
        return { messageId: 'mock-email-id-' + Date.now() };
      }
    };
  }
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV = process.env.ENCRYPTION_IV;
const algorithm = 'aes-256-cbc';
function encrypt(text) {
  if (!ENCRYPTION_KEY || !IV) throw new Error("Encryption key or IV not configured.");
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(IV, 'hex'));
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
function decrypt(text) {
  if (!ENCRYPTION_KEY || !IV) throw new Error("Encryption key or IV not configured.");
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(IV, 'hex'));
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function generateToken(userId, username) {
  if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is not defined in environment variables.");
  return jwt.sign({ userId, username }, process.env.JWT_SECRET, { expiresIn: '24h' });
}

const baseCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
};

const cookieOptions = {
  ...baseCookieOptions,
  maxAge: 24 * 60 * 60 * 1000
};

const clearCookieOptions = {
  ...baseCookieOptions
};

function authenticateToken(req, res, next) {
  const token = req.cookies.authToken || (req.headers.authorization ? req.headers.authorization.split(' ')[1] : null);
  const publicApiPaths = ['/api/check-auth'];
  if (!token) {
      if (publicApiPaths.includes(req.path)) {
          if (req.path === '/api/check-auth') {
              return res.status(401).json({ ok: false, authenticated: false, message: 'No token provided.' });
          }
      }
       if (!req.path.startsWith('/api/')) {
           return res.redirect('/?reason=noToken');
       }
       return res.status(401).json({ message: 'Authentication token required.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = db.prepare('SELECT current_token FROM users WHERE id = ?').get(decoded.userId);

    if (!user || !user.current_token || user.current_token !== token) {
        res.clearCookie('authToken', clearCookieOptions);
        res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
        if (publicApiPaths.includes(req.path)) {
             return res.status(401).json({ ok: false, authenticated: false, message: 'Invalid or expired token session.' });
        }
        return res.redirect('/logged-out?reason=expired');
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('authToken', clearCookieOptions);
    res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
     if (publicApiPaths.includes(req.path)) {
        return res.status(401).json({ ok: false, authenticated: false, message: 'Invalid token format or signature.' });
     }
    return res.redirect('/logged-out?reason=invalidToken');
  }
}

const tokens = new csrf();
const csrfProtection = (req, res, next) => {
  const skipCsrfPaths = ['/api/check-username-availability'];
  const method = req.method;
  const path = req.path;

  if (skipCsrfPaths.includes(path)) {
      return next();
  }

  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    let secret = req.cookies.csrfSecret;
    let token = res.locals.csrfToken;

    const isApiGet = path.startsWith('/api/');
    if (!secret || (!isApiGet && !token)) {
        try {
            secret = tokens.secretSync();
            const secretCookieOptions = { ...baseCookieOptions, httpOnly: true };
            res.cookie('csrfSecret', secret, secretCookieOptions);
            token = tokens.create(secret);
            res.locals.csrfToken = token;
        } catch (err) {
            console.error("Error generating CSRF secret/token:", err);
            return res.status(500).send("Internal Server Error generating CSRF token.");
        }
    } else if (secret && !token) {
         try {
             token = tokens.create(secret);
             res.locals.csrfToken = token;
         } catch(err) {
             console.error("Error creating CSRF token from existing secret:", err);
         }
    }
    next();
  } else {
    const secret = req.cookies.csrfSecret;
    const token = req.headers['x-csrf-token'];

    if (!secret || !token) {
        console.warn(`[CSRF ${method} ${path}] CSRF secret or token missing.`);
        return res.status(403).json({ message: 'CSRF validation failed (missing components).' });
    }

    try {
        if (tokens.verify(secret, token)) {
          next();
        } else {
          console.warn(`[CSRF ${method} ${path}] Verification FAILED.`);
          res.status(403).json({ message: 'Invalid CSRF Token.' });
        }
    } catch (err) {
         console.error(`[CSRF ${method} ${path}] Error verifying CSRF token:`, err);
         res.status(403).json({ message: 'CSRF validation error.' });
    }
  }
};

app.use(csrfProtection);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, storedHash) {
  try {
      if (!storedHash || typeof storedHash !== 'string') return false;
      const parts = storedHash.split(':');
      if (parts.length !== 2) return false;
      const salt = parts[0];
      const originalHash = parts[1];
      const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
      return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(originalHash, 'hex'));
  } catch (e) {
      console.error("Error verifying password:", e);
      return false;
  }
}

app.get('/', (req, res) => {
  const token = req.cookies.authToken;
  if (token) {
      try {
          jwt.verify(token, process.env.JWT_SECRET);
          return res.redirect('/dashboard');
      } catch (e) {
          res.clearCookie('authToken', clearCookieOptions);
          res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
      }
  }
  res.render('index', { title: 'Login or Register', csrfToken: res.locals.csrfToken });
});

app.get('/api/check-auth', authenticateToken, (req, res) => {
    if (req.user) {
        res.json({ ok: true, authenticated: true, username: req.user.username });
    } else {
        res.status(401).json({ ok: false, authenticated: false, message: 'Not authenticated.' });
    }
});

app.get('/api/check-username-availability', (req, res) => {
  try {
    const { username } = req.query;
    if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username.trim())) {
      return res.status(400).json({
        available: false,
        message: 'Invalid username format (3-20 chars, A-Z, 0-9, _).'
      });
    }
    const trimmedUsername = username.trim();
    let currentUserId = 0;
    const token = req.cookies.authToken || (req.headers.authorization ? req.headers.authorization.split(' ')[1] : null);
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            currentUserId = decoded.userId;
        } catch (e) {
            console.warn("Invalid token during username check, proceeding as anonymous.");
        }
    }
    const existingUser = db.prepare(
      'SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?'
    ).get(trimmedUsername, currentUserId);
    return res.json({
      available: !existingUser,
      message: existingUser ? 'Username already taken' : 'Username available'
    });
  } catch (error) {
    console.error('Error checking username availability:', error);
    return res.status(500).json({
      available: false,
      message: 'Error checking username availability'
    });
  }
});

app.get('/api/admin/username-history/:userId', authenticateToken, (req, res) => {
  try {
    const requestedUserId = parseInt(req.params.userId, 10);
    if (req.user.userId !== requestedUserId) {
        return res.status(403).json({ message: 'Forbidden: You can only view your own history.' });
    }
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(requestedUserId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const history = db.prepare(`
      SELECT old_username as username, changed_at
      FROM user_history
      WHERE user_id = ? AND old_username IS NOT NULL
      ORDER BY changed_at DESC
    `).all(requestedUserId);
    return res.json({
      currentUsername: user.username,
      history: history
    });
  } catch (error) {
    console.error('Error fetching username history:', error);
    return res.status(500).json({ message: 'Error fetching username history' });
  }
});

app.get('/user/:dashboardToken', authenticateToken, (req, res) => {
  if (!req.user) {
      return res.redirect('/?reason=noAuth');
  }
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const user = db.prepare('SELECT username, email FROM users WHERE dashboard_token = ? AND id = ?')
    .get(req.params.dashboardToken, req.user.userId);
  if (!user) {
    console.warn(`Access denied for user ${req.user.userId} to dashboard ${req.params.dashboardToken}`);
    return res.status(404).render('logged-out', {
        title: 'Not Found',
        reason: 'Dashboard not found or access denied.',
        csrfToken: res.locals.csrfToken
      });
  }
  res.render('user-dashboard', {
    username: user.username,
    email: user.email,
    dashboardToken: req.params.dashboardToken,
    csrfToken: res.locals.csrfToken,
    currentTime: '2025-04-20 01:04:43'
  });
});

app.get('/dashboard', authenticateToken, (req, res) => {
  if (!req.user) return res.redirect('/?reason=noAuth');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const user = db.prepare('SELECT dashboard_token FROM users WHERE id = ?')
    .get(req.user.userId);
  if (!user || !user.dashboard_token) {
      console.error(`User ${req.user.userId} is authenticated but missing dashboard token.`);
      return res.redirect('/logged-out?reason=error');
  }
  res.redirect(`/user/${user.dashboard_token}`);
});

app.post(
  '/api/register',
  [
    body('username').trim().isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters.')
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores.'),
    body('email').trim().isEmail().normalizeEmail().withMessage('Invalid email address.'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter.')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter.')
      .matches(/[0-9]/).withMessage('Password must contain a number.')
      .matches(/[@$!%*?&]/).withMessage('Password must contain a special character (@$!%*?&).'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) throw new Error('Passwords do not match.');
        return true;
      }),
    body('bypass2FA').optional().isBoolean()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const firstError = errors.array({ onlyFirstError: true })[0];
      return res.status(400).json({ message: firstError.msg, field: firstError.param });
    }
    try {
      const { username, email, password, bypass2FA } = req.body;
      const twoFactorMethod = 'email';
      const existingUser = db
        .prepare('SELECT id, LOWER(username) as lower_username, LOWER(email) as lower_email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)')
        .get(username, email);
      if (existingUser) {
        const isUsernameTaken = existingUser.lower_username === username.toLowerCase();
        return res.status(400).json({ message: isUsernameTaken ? 'Username is already taken.' : 'Email is already registered.' });
      }
      const hashedPassword = hashPassword(password);
      const timestamp = Date.now();
      const dashboardToken = crypto.randomBytes(32).toString('hex');
      const result = db.prepare(
        `INSERT INTO users (username, email, password, two_factor_method, bypass_2fa, dashboard_token, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(username, email, hashedPassword, twoFactorMethod, bypass2FA ? 1 : 0, dashboardToken, timestamp, timestamp);
      const userId = result.lastInsertRowid;
      if (!userId) throw new Error("Failed to insert user into database.");
       db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(userId, username, email, hashedPassword, timestamp);
      if (bypass2FA) {
        const token = generateToken(userId, username);
        db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
          .run(token, Date.now(), userId);
        res.cookie('authToken', token, cookieOptions);
        return res.status(201).json({
          message: 'Registration successful.',
          token: token,
          redirectUrl: `/user/${dashboardToken}`
        });
      } else {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 10 * 60 * 1000;
        try {
            await transporter.sendMail({
              from: process.env.SMTP_FROM || 'no-reply@example.com',
              to: email,
              subject: 'Your Verification Code',
              text: `Welcome! Your verification code is: ${code}. It expires in 10 minutes.`
            });
        } catch (mailError) {
             console.error("Failed to send verification email during registration:", mailError);
        }
        db.prepare('UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?')
          .run(code, expires, Date.now(), userId);
        return res.status(201).json({
          message: 'Registration successful. Please check your email for a verification code.',
          twoFactorRequired: true
        });
      }
    } catch (error) {
      console.error("Registration endpoint error:", error);
      return res.status(500).json({ message: 'Registration failed due to an internal server error.' });
    }
  }
);

app.post(
  '/api/login',
  [
    body('username').trim().notEmpty().withMessage('Username is required.'),
    body('password').exists().withMessage('Password is required.')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array({ onlyFirstError: true })[0].msg });
    }
    try {
      const { username, password } = req.body;
      const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
      if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ message: 'Invalid username or password.' });
      }
      if (user.two_factor_method === 'email' && !user.bypass_2fa) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 10 * 60 * 1000;
        try {
            await transporter.sendMail({
              from: process.env.SMTP_FROM || 'no-reply@example.com',
              to: user.email,
              subject: 'Your Login Verification Code',
              text: `Your verification code is: ${code}. It expires in 10 minutes.`
            });
        } catch (mailError) {
            console.error("Failed to send 2FA email during login:", mailError);
        }
        db.prepare('UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?')
          .run(code, expires, Date.now(), user.id);
        return res.json({
            message: "Verification required. Please check your email.",
            twoFactorRequired: true
        });
      }
      const token = generateToken(user.id, user.username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
        .run(token, Date.now(), user.id);
      res.cookie('authToken', token, cookieOptions);
      return res.json({
        message: 'Login successful.',
        token: token,
        redirectUrl: `/user/${user.dashboard_token}`
      });
    } catch (error) {
      console.error("Login endpoint error:", error);
      return res.status(500).json({ message: 'Login failed due to an internal server error.' });
    }
  }
);

app.post(
  '/api/verify-2fa',
  [
    body('username').trim().notEmpty(),
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid verification code format.' });
    }

    try {
      const { username, token } = req.body;
      const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);

      if (!user) {
        console.log(`[/api/verify-2fa] User not found: ${username}`);
        return res.status(400).json({ message: 'Invalid user.' });
      }

      let is2FAValid = false;
      if (user.two_factor_method === 'email') {
        if (user.email_code === token && user.email_code_expires > Date.now()) {
          is2FAValid = true;
          db.prepare('UPDATE users SET email_code = NULL, email_code_expires = NULL, updated_at = ? WHERE id = ?')
            .run(Date.now(), user.id);
        } else {
            console.log(`[/api/verify-2fa] Invalid/expired code attempt for user: ${username}. Code provided: ${token}, Expected: ${user.email_code}, Expires: ${user.email_code_expires}, Now: ${Date.now()}`);
        }
      } else {
          console.log(`[/api/verify-2fa] Email 2FA not enabled for user: ${username}`);
          return res.status(400).json({ message: 'Invalid verification method.' });
      }

      if (!is2FAValid) {
        return res.status(400).json({ message: 'Invalid or expired verification code.' });
      }

      const authToken = generateToken(user.id, user.username);
      db.prepare('UPDATE users SET current_token = ?, updated_at = ? WHERE id = ?')
        .run(authToken, Date.now(), user.id);

      res.cookie('authToken', authToken, cookieOptions);

      const responsePayload = {
        message: 'Verification successful.',
        token: authToken,
        redirectUrl: `/user/${user.dashboard_token}`
      };

      return res.json(responsePayload);

    } catch (error) {
      console.error("[/api/verify-2fa] Error:", error);
      return res.status(500).json({ message: '2FA verification failed due to an internal server error.' });
    }
  }
);


app.post('/api/resend-2fa', (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ message: 'Username is required.' });
    const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username);
    if (!user) return res.status(400).json({ message: 'User not found.' });
    if (user.two_factor_method !== 'email') return res.status(400).json({ message: 'Email 2FA not enabled for this user.' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000;
    transporter.sendMail({
      from: process.env.SMTP_FROM || 'no-reply@example.com',
      to: user.email,
      subject: 'Your New Verification Code',
      text: `Your new verification code is: ${code}. It expires in 10 minutes.`
    }).then(() => {
        console.log(`Resent 2FA code email to ${user.email}`);
    }).catch(error => {
      console.error(`Error resending 2FA email to ${user.email}:`, error);
    });
    db.prepare('UPDATE users SET email_code = ?, email_code_expires = ?, updated_at = ? WHERE id = ?')
      .run(code, expires, Date.now(), user.id);
    console.log(`Updated 2FA code in DB for user ${username}`);
    return res.json({ message: 'A new verification code has been sent (if email configured).' });
  } catch (error) {
    console.error("Resend 2FA error:", error);
    return res.status(500).json({ message: 'Failed to resend verification code due to an internal server error.' });
  }
});

app.post('/api/logout', authenticateToken, (req, res) => {
  try {
    const userId = req.user?.userId;
    if (userId) {
        db.prepare('UPDATE users SET current_token = NULL, updated_at = ? WHERE id = ?')
          .run(Date.now(), userId);
        console.log(`User ${userId} logged out. Invalidated token in DB.`);
    } else {
        console.warn("Logout attempt without a valid user session (req.user missing).");
    }
    res.clearCookie('authToken', clearCookieOptions);
    res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ message: 'Logout failed due to an internal server error.' });
  }
});

app.post('/api/forgot-password', [body('email').trim().isEmail().normalizeEmail()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      console.log(`Invalid email format in forgot password request: ${req.body.email}`);
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  }
  const { email } = req.body;
  try {
      const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)').get(email);
      if (!user) {
        console.log(`Password reset requested for non-existent or unverified email: ${email}`);
      } else {
        const token = crypto.randomBytes(32).toString('hex');
        const expires = Date.now() + 3600000;
        db.prepare('UPDATE users SET password_reset_token = ?, password_reset_expires = ?, updated_at = ? WHERE id = ?')
          .run(token, expires, Date.now(), user.id);
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${token}&email=${encodeURIComponent(user.email)}`;
        transporter.sendMail({
          from: process.env.SMTP_FROM || 'no-reply@example.com',
          to: user.email,
          subject: 'Password Reset Request',
          text: `You (or someone else) requested a password reset for your account.\n\nClick the link below to reset your password:\n${resetUrl}\n\nThis link will expire in 1 hour. If you did not request this, please ignore this email and your password will remain unchanged.`
        }).then(() => {
            console.log(`Password reset email sent to ${user.email}`);
        }).catch(error => {
          console.error(`Error sending password reset email to ${user.email}:`, error);
        });
      }
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({ message: 'An error occurred. If an account exists, an email may have been sent.' });
  }
});

app.get('/reset-password', (req, res) => {
  const { token, email } = req.query;
  if (!token || !email) return res.status(400).send('Invalid or incomplete password reset link.');
  res.render('reset-password', { token, email, csrfToken: res.locals.csrfToken });
});

app.post('/api/reset-password', [
  body('email').trim().isEmail().normalizeEmail(),
  body('token').notEmpty(),
  body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter.')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter.')
      .matches(/[0-9]/).withMessage('Password must contain a number.')
      .matches(/[@$!%*?&]/).withMessage('Password must contain a special character (@$!%*?&).'),
  body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) throw new Error('Passwords do not match.');
        return true;
      })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array({ onlyFirstError: true })[0].msg });
  const { email, token, password } = req.body;
  try {
      const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)').get(email);
      if (!user || user.password_reset_token !== token || user.password_reset_expires < Date.now()) {
        console.log(`Invalid reset attempt for email ${email}. Token provided: ${token}`);
        return res.status(400).json({ message: 'Invalid or expired password reset link.' });
      }
      const hashedPassword = hashPassword(password);
      db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(user.id, user.username, user.email, user.password, Date.now());
      db.prepare('UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL, current_token = NULL, updated_at = ? WHERE id = ?')
        .run(hashedPassword, Date.now(), user.id);
      console.log(`Password successfully reset for user ${user.id} (${user.username})`);
      res.json({ message: 'Password reset successful. You can now log in with your new password.' });
  } catch (error) {
      console.error("Reset password API error:", error);
      res.status(500).json({ message: 'Failed to reset password due to an internal server error.' });
  }
});

app.post('/api/settings/update', authenticateToken, [
  body('setting').trim().notEmpty().withMessage('Setting name is required.'),
  body('value').trim()
], async (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Authentication required.' });
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array({ onlyFirstError: true })[0].msg });
  const { setting, value } = req.body;
  const userId = req.user.userId;
  try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      if (!user) return res.status(404).json({ message: 'User not found.' });
      let updateStmt;
      let historyData = { userId: user.id, old_username: user.username, old_email: user.email, old_password: user.password, changed_at: Date.now() };
      let newToken = null;
      switch (setting) {
          case 'username':
              if (!value || !/^[a-zA-Z0-9_]{3,20}$/.test(value)) {
                  return res.status(400).json({ message: 'Invalid username format (3-20 chars, A-Z, 0-9, _).' });
              }
              if (value.toLowerCase() === user.username.toLowerCase()) {
                  return res.json({ message: 'Username is the same, no changes made.' });
              }
              const existingUser = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?').get(value, userId);
              if (existingUser) return res.status(400).json({ message: 'Username is already taken.' });
              updateStmt = db.prepare('UPDATE users SET username = ?, updated_at = ? WHERE id = ?');
              updateStmt.run(value, Date.now(), userId);
              console.log(`Username updated for user ${userId} from ${user.username} to ${value}`);
              newToken = generateToken(userId, value);
              db.prepare('UPDATE users SET current_token = ? WHERE id = ?').run(newToken, userId);
              break;
          case 'email':
              if (!value || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                 return res.status(400).json({ message: 'Invalid email address format.' });
              }
               if (value.toLowerCase() === user.email.toLowerCase()) {
                   return res.json({ message: 'Email is the same, no changes made.' });
               }
              const existingEmail = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id != ?').get(value, userId);
              if (existingEmail) return res.status(400).json({ message: 'Email is already registered to another account.' });
              updateStmt = db.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?');
               updateStmt.run(value, Date.now(), userId);
               console.log(`Email updated for user ${userId} from ${user.email} to ${value}`);
              break;
          case 'password':
              if (!value || value.length < 8 || !/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/[0-9]/.test(value) || !/[@$!%*?&]/.test(value)) {
                  return res.status(400).json({ message: 'New password does not meet complexity requirements.' });
              }
              const hashedPassword = hashPassword(value);
              updateStmt = db.prepare('UPDATE users SET password = ?, updated_at = ?, current_token = NULL WHERE id = ?');
              updateStmt.run(hashedPassword, Date.now(), userId);
              console.log(`Password updated for user ${userId}. Current session invalidated.`);
              res.clearCookie('authToken', clearCookieOptions);
              res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
              break;
          default:
              return res.status(400).json({ message: 'Invalid setting specified.' });
      }
      db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(historyData.userId, historyData.old_username, historyData.old_email, historyData.old_password, historyData.changed_at);
      if (newToken) {
          res.cookie('authToken', newToken, cookieOptions);
      }
      return res.json({ message: `${setting.charAt(0).toUpperCase() + setting.slice(1)} updated successfully.` + (setting === 'password' ? ' Please log in again.' : '') });
  } catch (error) {
    console.error(`Error updating setting '${setting}' for user ${userId}:`, error);
    return res.status(500).json({ message: `Could not update ${setting} due to an internal server error.` });
  }
});

app.get('/logged-out', (req, res) => {
  res.clearCookie('authToken', clearCookieOptions);
  res.clearCookie('csrfSecret', { ...clearCookieOptions, httpOnly: true });
  res.render('logged-out', { reason: req.query.reason, csrfToken: res.locals.csrfToken });
});

app.use('/favicon.ico', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.use((req, res) => {
  console.log(`404 Not Found for route: ${req.method} ${req.originalUrl}`);
  if (req.accepts('html')) {
    res.status(404).render('logged-out', {
      title: '404 Not Found',
      reason: 'The page you requested could not be found.',
      csrfToken: res.locals.csrfToken
    });
  } else if (req.accepts('json')) {
    res.status(404).json({ message: 'Endpoint not found.' });
  } else {
    res.status(404).type('txt').send('Not Found.');
  }
});

app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack || err);
    const message = process.env.NODE_ENV === 'production' ? 'An internal server error occurred.' : err.message;
    res.status(err.status || 500);
    if (req.accepts('html')) {
        res.render('logged-out', { title: 'Server Error', reason: message, csrfToken: res.locals.csrfToken });
    } else if (req.accepts('json')) {
        res.json({ message: message });
    } else {
        res.type('txt').send(`Server Error: ${message}`);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on http://localhost:${PORT}`);
});
