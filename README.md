# Simple SPA with 2FA

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
   JWT_SECRET=secret_phrase
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=465
   SMTP_SECURE=true
   SMTP_USER=your_email@gmail.com
   SMTP_PASS=YourEmailPassword!
   DB_PATH=./database.db
   ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
   ALLOWED_HOSTS=localhost:3000,yourdomain.com
   ENCRYPTION_KEY=
   ENCRYPTION_IV=
   CSRF_SECRET=
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
