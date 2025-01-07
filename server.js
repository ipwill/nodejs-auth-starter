import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import speakeasy from 'speakeasy';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const db = new Database(process.env.DB_PATH || 'database.db');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.json());
app.use(helmet());

const isDevelopment = process.env.NODE_ENV === 'development';

app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use('/js', express.static(path.join(__dirname, 'public', 'js')));
app.use('/webfonts', express.static(path.join(__dirname, 'public', 'webfonts')));

if (isDevelopment) {
  app.use('/assets', express.static(path.join(__dirname, 'assets')));
} else {
  app.use('/assets', express.static(path.join(__dirname, 'assets'), { maxAge: '1y' }));
}

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self'; font-src 'self'; style-src 'self'; script-src 'self' https://cdn.jsdelivr.net;"
  );
  next();
});

if (isDevelopment) {
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
  });
}

function updateSchema() {
  try {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          two_factor_method TEXT,
          totp_secret TEXT,
          email_code TEXT,
          bypass_2fa BOOLEAN DEFAULT false
        );
      `);
    })();
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

updateSchema();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

function generateToken(userId, username) {
  return jwt.sign({ userId, username }, process.env.JWT_SECRET, { expiresIn: '24h' });
}

app.get('/', (req, res) => {
  res.render('index', { title: 'Login App' });
});

app.post('/register', async (req, res) => {
  try {
    const { username, password, twoFactorMethod, bypass2FA } = req.body;
    if (!username || !password || (bypass2FA === undefined && !twoFactorMethod)) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }
    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existingUser) {
      return res.status(400).json({ message: 'Username already taken.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const bypass2FAValue = bypass2FA ? 1 : 0;
    const result = db.prepare(`
      INSERT INTO users (username, password, two_factor_method, bypass_2fa)
      VALUES (?, ?, ?, ?)
    `).run(username, hashedPassword, bypass2FAValue ? null : twoFactorMethod, bypass2FAValue);
    if (!bypass2FA && twoFactorMethod === 'totp') {
      const secret = speakeasy.generateSecret({ name: `App:${username}` });
      db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret.base32, result.lastInsertRowid);
    }
    const token = generateToken(result.lastInsertRowid, username);
    return res.status(201).json({
      message: 'Registration successful',
      bypass2FA,
      twoFactorMethod,
      token
    });
  } catch (error) {
    return res.status(500).json({ message: 'Registration failed', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password, bypass2FA } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    if (user.two_factor_method && !bypass2FA && !user.bypass_2fa) {
      if (user.two_factor_method === 'email') {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        transporter.sendMail({
          from: process.env.SMTP_USER,
          to: username,
          subject: '2FA Verification Code',
          text: `Your verification code is: ${code}`
        });
        db.prepare('UPDATE users SET email_code = ? WHERE id = ?').run(code, user.id);
      }
      return res.json({ twoFactorRequired: true, twoFactorMethod: user.two_factor_method });
    }
    const token = generateToken(user.id, user.username);
    return res.json({ token });
  } catch (error) {
    return res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

app.post('/verify-2fa', (req, res) => {
  try {
    const { username, token } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ message: 'Invalid user.' });
    }
    if (user.two_factor_method === 'totp') {
      const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token
      });
      if (!verified) {
        return res.status(400).json({ message: 'Invalid TOTP code.' });
      }
    } else if (user.two_factor_method === 'email') {
      if (user.email_code !== token) {
        return res.status(400).json({ message: 'Invalid email code.' });
      }
    }
    const authToken = generateToken(user.id, user.username);
    return res.json({ token: authToken });
  } catch (error) {
    return res.status(500).json({ message: '2FA verification failed', error: error.message });
  }
});

app.get('/user/:username', (req, res) => {
  let token;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.query.token) {
    token = req.query.token;
  } else {
    return res.status(401).send('<h1>Unauthorized</h1><p>No token provided. Please log in again.</p>');
  }
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).send('<h1>Unauthorized</h1><p>Invalid token. Please log in again.</p>');
  }
  if (decoded.username !== req.params.username) {
    return res.status(403).send('<h1>Forbidden</h1><p>Access denied.</p>');
  }
  const user = db.prepare('SELECT username FROM users WHERE username = ?').get(req.params.username);
  if (!user) {
    return res.status(404).send('<h1>Not Found</h1><p>User not found.</p>');
  }
  res.render('user-dashboard', { username: user.username });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});