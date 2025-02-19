# Real-time User Authentication (Vanilla JavaScript)

A foundation for building custom authentication systems in NodeJS using vanilla JavaScript.

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

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cgtwig/nodejs-auth-starter
   cd nodejs-auth-starter
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Rename `.env-example` file to `.env` and fill-in blank values:**  
   (or create a new file named `.env` in project root with the below contents)
   
   Values can be generated using the terminal commands below. Values are needed for `JWT_SECRET`, `ENCRYPTION_KEY`, `ENCRYPTION_IV`, and `CSRF_SECRET`)
   ```bash
   openssl rand -hex 32   # For JWT_SECRET, ENCRYPTION_KEY, and CSRF_SECRET (generate different one for each)
   openssl rand -hex 16   # For ENCRYPTION_IV
   ```

   #### `.env-example`
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development
   # JWT Secret Key (Used for Authentication Tokens)
   JWT_SECRET=
   # MailHog SMTP Configuration (Local Development)
   SMTP_HOST=127.0.0.1
   SMTP_PORT=1025
   SMTP_SECURE=false
   # SQLite Database File
   DB_PATH=./database.db
   # Allowed Origins (Frontend URLs that can access the backend)
   ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
   # Allowed Hosts (Prevent Host Header Injection)
   ALLOWED_HOSTS=localhost:3000,127.0.0.1:3000
   # Encryption Keys (Generate Secure Random Values)
   ENCRYPTION_KEY=
   ENCRYPTION_IV=
   # CSRF Protection Secret
   CSRF_SECRET=
   ```
   
6. **2FA Setup**  
   - **Windows:**
     Download `MailHog.exe` from [MailHog Releases](https://github.com/mailhog/MailHog/releases)
   - **MacOSX/Linux:** You can quickly get MailHog running with this script. Just copy and paste into your terminal. It will install/launch a fresh installation of MailHog on port 8025.
    
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
   
   **OR...** MailHog can alternatively be ran with Docker using this one-liner (optional):
   Note: Docker needs to be installed for command to work.
   ```bash
   docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
   ```
   MailHog UI can be accessed in the browser at:
     [http://localhost:8025](http://localhost:8025).

   if everything is working correctly - you should see the MailHog Web UI:
   ![mailhog-ui-ss.png](images/mailhog-ui-ss.png)  
   *mailhog-ui-ss.png*

7. **Build client-side JS**
   ```bash
   npm run build
   ```
   
8. **Start server:**
   ```bash
   # hot reloading enabled
   npm run dev

   # hot reloading disabled
   npm start
   ```
   
   You can now go to... [http://localhost:3000](http://localhost:3000)
   
   ***
   
   If you find any errors please [open an issue](https://github.com/cgtwig/nodejs-auth-starter/issues). There is definately room for immprovment here - if you want to help out, submit a pull request.

## Screenshots

![login-ss.png](images/login-ss.png)  
*login-ss.png*

![register-ss.png](images/register-ss.png)  
*register-ss.png*

![2fa-ss.png](images/2fa-ss.png)  
*2fa-ss.png*
   
## Dependencies

- **Backend:** Node.js, Express, Better-SQLite3, JWT, Nodemailer (2FA)
- **Frontend:** Vanilla JavaScript, EJS templates, CSS
- **Bundling:** Webpack
- **Development Tools:** MailHog (optional)

## Troubleshooting

- **.env file (required)**  
  Make sure the following line exists and is not commented out `SMTP_HOST=127.0.0.1`

- **Build bundle: (required)**  
  Run `npm run build`, clear browser cache, and restart server.

## License
MIT
