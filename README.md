# Real-time User Authentication (Vanilla JavaScript)

A basic user authentication foundation built with vanilla JavaScript, featuring built-in 2FA support, secure password hashing, and JWT-based authentication. It includes a pre-styled front end with light and dark themes and uses a built-in better-sqlite3 database for user data. Designed to be lightweight (~350KiB) and unopinionated, this project aims to provide a head start for developing custom user authentication in Node.js web apps.

**Key Features:**

*   **Database:** `better-sqlite3` for local user data storage.
*   **2FA:** Implemented with MailHog for testing. Production requires a real mail server.
*   **Security:** Includes hardening middleware.
*   **Frontend:** Styled UI with light/dark themes.
*   **Bundler:** Webpack for client-side assets.
*   **User Dashboard:** Dynamic URL generation.
*   **Authentication:** Secure login with JWT (JSON Web Token) authentication.
*   **Email 2FA:** Pre-issued token verification.
*   **Templates:** `.ejs` UI templates.
*   **Security:** Helmet for CSRF protection and secure HTTP headers.
*   **Configuration:** Webpack configuration included.

## Database Schema

```sql
-- Users Table
CREATE TABLE users (
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

-- User History Table
CREATE TABLE user_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    old_username TEXT,
    old_email TEXT,
    old_password TEXT,
    changed_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## API Routes

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/verify-2fa` - Verify 2FA code
- `POST /api/logout` - User logout

### Password Management
- `POST /api/forgot-password` - Request password reset
- `GET /reset-password` - Display password reset form
- `POST /api/reset-password` - Process password reset

### User Settings
- `POST /api/settings/update` - Update user settings
- `GET /user/:dashboardToken` - Access user dashboard
- `GET /dashboard` - Main dashboard

## Setup

1.  **Clone:**
    ```bash
    git clone https://github.com/cgtwig/nodejs-auth-starter
    cd nodejs-auth-starter
    ```

2.  **Install:**
    ```bash
    npm install
    ```

3.  **Configure Environment (`.env`)**

    *  Rename `.env-example` to `.env` (or create file named `.env` with the contents below)
    *  Generate the following values for `.env`

    Using terminal (openssl required):  
    ```bash
    openssl rand -hex 32   # JWT_SECRET
    openssl rand -hex 32   # ENCRYPTION_KEY
    openssl rand -hex 32   # CSRF_SECRET
    openssl rand -hex 16   # ENCRYPTION_IV
    ```

    *   **Your `.env` file should look like this**

    ```env
    # Server Configuration
    PORT=3000
    NODE_ENV=development
    
    # MailHog SMTP Configuration (Local Development)
    SMTP_HOST=127.0.0.1
    SMTP_PORT=1025
    SMTP_SECURE=false

    # SQLite Database File
    DB_PATH=./database.db

    # Allowed Origins (CORS)
    ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

    # Allowed Hosts (Host Header Injection Prevention)
    ALLOWED_HOSTS=localhost:3000,127.0.0.1:3000

    # REQUIRED
    JWT_SECRET=
    ENCRYPTION_KEY=
    CSRF_SECRET=
    ENCRYPTION_IV=
    ```

4.  **2FA (MailHog):**

    Download and run MailHog for your platform:
    ```bash
    # Using curl (recommended)
    curl -s https://raw.githubusercontent.com/mailhog/MailHog/master/scripts/install.sh | sh

    # Or using Docker
    docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
    ```

    Access MailHog UI: [http://localhost:8025](http://localhost:8025)

5.  **Build:**
    ```bash
    npm run build
    ```

6.  **Start:**
    ```bash
    # Development (hot reloading)
    npm run dev

    # Production
    npm start
    ```

    Access the application at [http://localhost:3000](http://localhost:3000).

## Screenshots

| Login | Register | 2FA Verification |
|-------|----------|------------------|
| ![login-ss.png](images/login-ss.png) | ![register-ss.png](images/register-ss.png) | ![2fa-ss.png](images/2fa-ss.png) |

## Dependencies

*   **Backend:** Node.js, Express, Better-SQLite3, JWT, Nodemailer
*   **Frontend:** Vanilla JavaScript, EJS templates, CSS
*   **Bundling:** Webpack
*   **Development:** MailHog (optional)

## Troubleshooting

*   **.env Configuration:** Ensure `SMTP_HOST=127.0.0.1` is present and uncommented in your `.env` file.
*   **Build Output:** If experiencing issues, run `npm run build`, clear your browser cache, and restart the server.

## License

MIT
