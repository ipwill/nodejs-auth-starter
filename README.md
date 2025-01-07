# Simple SPA with 2FA
[![NodeJS with Webpack](https://github.com/cgtwig/nodejs-login-2fa/actions/workflows/webpack.yml/badge.svg)](https://github.com/cgtwig/nodejs-login-2fa/actions/workflows/webpack.yml)

A minimal single-page application (SPA) for user authentication with Two-Factor Authentication (TOTP/email) built using Node.js, Express, and modern JavaScript.

## Features

- User registration with 2FA
- Secure login with JWT
- TOTP or email-based verification
- SQLite for persistence
- Responsive UI with flat design

## Setup

1. Clone the repo:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure `.env`:
   Create a `.env` file with:
   ```env
   PORT=3000
   NODE_ENV=development
   JWT_SECRET=s3cUr3R@nd0m$tr1ng
   SMTP_HOST=smtp.example.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_USER=your_email@example.com
   SMTP_PASS=your_email_password
   DB_PATH=./database.db
   ```

4. Build the app:
   ```bash
   npm run build
   ```

5. Start the server:
   ```bash
   npm start
   ```

   App will run at `http://localhost:3000`.

## Dev Mode

Run with hot-reloading:
   ```bash
   npm run dev
   ```

Serve front-end with Webpack:
   ```bash
   npm run serve
   ```

## Tech Stack

- **Backend**: Node.js, Express, SQLite
- **Frontend**: Vanilla JS, EJS templates
- **Styling**: CSS with flat design

## License

MIT
