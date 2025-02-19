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

3.  **Configure Environment:**

    *   Rename `.env-example` to `.env`.
    *   Populate the `.env` file with secure values.  Use the following commands to generate secrets:

    ```bash
    openssl rand -hex 32   # For JWT_SECRET, ENCRYPTION_KEY, and CSRF_SECRET (generate different one for each)
    openssl rand -hex 16   # For ENCRYPTION_IV
    ```

    *   **Example `.env`:**

    ```env
    # Server Configuration
    PORT=3000
    NODE_ENV=development

    # JWT Secret Key
    JWT_SECRET=<generated_secret>

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

    # Encryption Keys
    ENCRYPTION_KEY=<generated_secret>
    ENCRYPTION_IV=<generated_iv>

    # CSRF Protection Secret
    CSRF_SECRET=<generated_secret>
    ```

4.  **2FA (MailHog):**

    *   **Option 1 (Executable):**  Download `MailHog.exe` from [MailHog Releases](https://github.com/mailhog/MailHog/releases) (Windows).  For MacOS/Linux, use the script below:

        ```bash
        OS=$(uname -s)
        ARCH=$(uname -m)

        if [ "$OS" = "Darwin" ]; then
            PLATFORM="macOS"
        elif [ "$OS" = "Linux" ]; then
            if [ -f /etc/nixos/version ]; then
                PLATFORM="nixos"
            else
                PLATFORM="linux"
            fi
        else
            echo "Unsupported OS. Please install MailHog manually."
            exit 1
        fi

        if [ "$ARCH" = "x86_64" ]; then
            ARCH="amd64"
        elif [ "$ARCH" = "aarch64" ]; then
            ARCH="arm"
        else
            echo "Unsupported architecture. Please install MailHog manually."
            exit 1
        fi

        if [ "$PLATFORM" = "nixos" ]; then
            echo "Detected NixOS. Installing MailHog via Nix package manager."
            nix-env -iA nixos.mailhog
            exit 0
        fi

        URL="https://github.com/mailhog/MailHog/releases/latest/download/MailHog_${PLATFORM}_${ARCH}"

        kill -9 $(lsof -ti:1025) 2>/dev/null || true

        if ! command -v wget &> /dev/null; then
            echo "wget not found. Installing..."
            nix-env -iA nixos.wget
        fi

        mkdir -p ~/bin && wget -qO ~/bin/MailHog "$URL" && chmod +x ~/bin/MailHog && ~/bin/MailHog
        ```

    *   **Option 2 (Docker):**

        ```bash
        docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
        ```

    *   Access MailHog UI: [http://localhost:8025](http://localhost:8025)

        ![mailhog-ui-ss.png](images/mailhog-ui-ss.png)

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

![login-ss.png](images/login-ss.png)

![register-ss.png](images/register-ss.png)

![2fa-ss.png](images/2fa-ss.png)

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
