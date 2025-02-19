# Real-time User Authentication (Vanilla JavaScript)

A simple lightweight (~350KiB) user auth web app that includes built-in 2FA (mandatory), password validation, password update/reset and JWT-based authentication. The app comes with a styled responsive frontend UI that comes with dark/light theme support, dynamic user profiles, and more. This project aims to provide a head start for developing custom user authentication in Node.js web apps.

## Features:

*   **Database:** `better-sqlite3` for user data (required)
*   **2FA:** 
*   **Frontend:** Styled UI (light/dark theme)
*   **Bundler:** Webpack for client-side assets (bundle.js)
*   **User account page** Dynamic user dashboard creation
*   **Authentication:** Secure JWT login (JSON Web Token)
*   **Email 2FA:** Mandatory multi-factor authentication
*   **Templates:** `.ejs` UI templates
*   **Other:** Helmet for CSRF protection & secure HTTP headers

## Database schema:

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

## API routes:

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/verify-2fa` - Verify 2FA code
- `POST /api/logout` - User logout

### Password management
- `POST /api/forgot-password` - Request password reset
- `GET /reset-password` - Display password reset form
- `POST /api/reset-password` - Process password reset

### User settings
- `POST /api/settings/update` - Update user settings
- `GET /user/:dashboardToken` - Access user dashboard
- `GET /dashboard` - Main dashboard

## Setup:

1.  **Clone:**
    ```bash
    git clone https://github.com/cgtwig/nodejs-auth-starter
    cd nodejs-auth-starter
    ```

2.  **Install:**
    ```bash
    npm install
    ```

3.  **Configure environment (`.env`)**

    **(Required)** Rename `.env-example` to `.env` (or create file named `.env` with the contents below)

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

    **(Required)** Generate the following values for the values at the end of the `.env`
    ```bash
    # run in terminal (openssl will need to be installed)
    openssl rand -hex 32   # JWT_SECRET
    openssl rand -hex 32   # ENCRYPTION_KEY
    openssl rand -hex 32   # CSRF_SECRET
    openssl rand -hex 16   # ENCRYPTION_IV
    ```

5.  **2FA: MailHog (recommended)**

    MailHog allows 2FA to work without needing to configure an actual mail server. Choose the installation method that works best for your system:

    **Option 1:** Binary (Windows)
    - Download the latest `MailHog.exe` from [MailHog Releases](https://github.com/mailhog/MailHog/releases)
    - Double-click to run

    **Option 2:** Docker (Windows/macOS/Linux)
    ```bash
    docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
    ```

    **Option 3:** GO (Windows/macOS/Linux)
    ```bash
    go install github.com/mailhog/MailHog@latest
    ```
      
    **Option 4:** One-liner command to download/run (macOS/Linux) **[recommended]**
    ```bash
    curl -L $(curl -s https://api.github.com/repos/mailhog/MailHog/releases/latest | grep browser_download_url | grep $(uname -s)_$(uname -m) | cut -d '"' -f 4) -o ~/mailhog && chmod +x ~/mailhog && ~/mailhog
    ```

    Once installed, access the MailHog UI at: [http://localhost:8025](http://localhost:8025)

    Note: For all methods, ensure ports 1025 (SMTP) and 8025 (Web UI) are available.

6.  **Build:**
    ```bash
    npm run build
    ```

7.  **Start:**
    ```bash
    # Development (hot reloading)
    npm run dev

    # Production
    npm start
    ```

    Access the application at [http://localhost:3000](http://localhost:3000)

## Screenshots:

| Login | Register | 2FA Verification |
|-------|----------|------------------|
| ![login-ss.png](images/login-ss.png) | ![register-ss.png](images/register-ss.png) | ![2fa-ss.png](images/2fa-ss.png) |

## Dependencies:

*   **Backend:** Node.js, Express, Better-SQLite3, JWT, Nodemailer
*   **Frontend:** Vanilla JavaScript, EJS templates, CSS
*   **Bundling:** Webpack
*   **Development:** MailHog (optional)

## Troubleshooting:

*   **.env configuration:** Ensure `SMTP_HOST=127.0.0.1` is present and uncommented in your `.env` file.
*   **Build output:** If experiencing issues, run `npm run build`, clear your browser cache, and restart the server.

## License:

MIT
