## Real-time User Authentication (Vanilla JavaScript)

Node.js authentication starter using Express and Better-SQLite3. Provides a secure foundation including email-based 2FA, JWT sessions, CSRF protection, and Helmet security headers. Features a responsive, webpack-bundled EJS frontend. Supports user management tasks like password resets and account history tracking via SQLite. Includes rate limiting and CORS configuration.

### Features

- **SQLite Database:** `better-sqlite3` for user data persistence
- **JWT Authentication:** Token-based secure authentication
- **Mandatory 2FA:** Email-based verification system
- **Security Headers:** Helmet.js for CSRF and HTTP security
- **Asset Bundling:** Webpack 5 for client-side optimization
- **Template Engine:** EJS for server-side rendering
- **Dynamic UI:** Responsive layout with theme switching
- **State Management:** Real-time updates without frameworks
- **User Dashboard:** Profile and account management
- **Rate Limiting:** Request throttling protection

### Requirements

- **Node.js:** 18.x or higher
- **npm:** 8.x or higher
- **OpenSSL:** Required for security keys
- **Ports:**
  - 3000 (app server)
  - 1025 (MailHog SMTP)
  - 8025 (MailHog UI)
- **OS:** Windows 10/11, macOS 10.15+, or Linux (Ubuntu 20.04+, Debian 11+)

### Dependencies

| Category | Package | Version | Purpose |
|----------|---------|---------|----------|
| **Core** | express | ^4.18.x | Server |
| | better-sqlite3 | ^11.8.x | SQLite database |
| | jsonwebtoken | ^9.0.x | JWT authentication |
| | nodemailer | ^6.9.x | E-mail service |
| | dotenv | ^16.4.x | .env support |
| | axios | ^1.6.x | HTTP client (frontend) |
| **Security** | helmet | ^7.1.x | HTTP headers |
| | express-rate-limit | ^7.1.x | Rate limiting |
| | csrf | ^3.1.x | CSRF token protection |
| | cookie-parser | ^1.4.x | Cookie handling |
| | crypto (built-in) | N/A | Encryption/hashing |
| **Validation** | express-validator | ^7.0.x | Input validation |
| **Frontend** | ejs | ^3.1.x | Template engine |
| | cors | ^2.8.x | CORS middleware |
| **Development** | mailhog | N/A | 2FA testing |
| | webpack | ^5.90.x | Asset bundling |
| | @babel/core | ^7.23.x | JS transpiling |

### Database schema

```sql
-- Users table
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

-- User history table to track changes
CREATE TABLE IF NOT EXISTS user_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  old_username TEXT,
  old_email TEXT,
  old_password TEXT,
  changed_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### API routes

**Authentication**
- `GET /api/check-auth` - Check if user is authenticated
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/verify-2fa` - Verify 2FA code
- `POST /api/resend-2fa` - Resend 2FA code
- `POST /api/logout` - User logout

**Password management**
- `POST /api/forgot-password` - Request password reset
- `GET /reset-password` - Display password reset form
- `POST /api/reset-password` - Process password reset

**User settings & Data**
- `POST /api/settings/update` - Update user settings (username, email, password)
- `GET /api/check-username-availability` - Check if username is available
- `GET /api/admin/username-history/:userId` - Get username change history for a user

**Frontend Routes (Server-Rendered)**
- `GET /user/:dashboardToken` - Access user dashboard
- `GET /dashboard` - Redirects to user-specific dashboard
- `GET /` - Login/Register page
- `GET /logged-out` - Logout confirmation page

### Setup

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

4.  **2FA: MailHog (recommended)**

    One-liner commands to download and run MailHog

     a) **macOS/Linux/Unix (terminal):**
    ```bash
    sh -c 'os=$(uname -s); arch=$(uname -m); V="v1.0.1"; case "$os-$arch" in Linux-x86_64|Linux-amd64) suffix="linux_amd64";; Linux-aarch64|Linux-arm64) suffix="linux_arm64";; Darwin-x86_64|Darwin-amd64) suffix="darwin_amd64";; Darwin-arm64) suffix="darwin_amd64"; echo "NOTE: Using amd64 binary via Rosetta 2 on arm64 Mac.";; *) echo "Error: Unsupported OS/Arch: $os-$arch"; exit 1;; esac; echo "Downloading MailHog_$suffix..."; curl -fL "https://github.com/mailhog/MailHog/releases/download/$V/MailHog_$suffix" -o mailhog && chmod +x mailhog && echo "Starting MailHog..." && ./mailhog || echo "MailHog download or execution failed."'
    ```
    
    b) **Windows (Powershell):**
    ```powershell
    Invoke-WebRequest -Uri "https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_windows_amd64.exe" -OutFile "mailhog.exe" ; Start-Process -FilePath ".\mailhog.exe"
    ```
    
    c) **(Optional)** Docker
    ```
    docker run --rm -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog
    ```
    
    Note: Access MailHog UI at [http://localhost:8025](http://localhost:8025) after installation

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

### Screenshots

| Login (light) | Register (light) |
|-------|----------|
| ![light-login.png](public/images/light-login.png) | ![light-register.png](public/images/light-register.png) | 
  
| Login (dark) | Register (dark) |
|----------|------------------|
| ![dark-login.png](public/images/dark-login.png) | ![dark-register.png](public/images/dark-register.png) |

### License

MIT
