# Security Policy

Security is a priority for nodejs-auth-starter, maintained solely by httpcg. This project offers developers a secure starting template for custom Node.js authentication, including JWT, 2FA, CSRF protection, password hashing, and security headers. It allows users to save time and extend a secure base for their needs. We appreciate responsible disclosure of any findings.

## Supported Versions

You can find the latest release on the [Releases page](https://github.com/httpcg/nodejs-auth-starter/releases).

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report vulnerabilities **privately** using GitHub's security advisory feature.

1.  Go to the ["Security" tab of the `nodejs-auth-starter` repository](https://github.com/httpcg/nodejs-auth-starter/security).
2.  Click on "Report a vulnerability".
3.  Fill out the form with details about the vulnerability. Please include:
    *   A clear description of the vulnerability.
    *   Steps to reproduce the vulnerability.
    *   The potential impact of the vulnerability.
    *   Any suggested mitigation or fix, if known.
    *   The version(s) affected.

**Alternatively, if you prefer, you can use this direct link:**
[Report a Vulnerability](https://github.com/httpcg/nodejs-auth-starter/security/advisories/new)

**What to Expect:**

*   You should receive an initial acknowledgement within **48 hours**.
*   We will keep you informed of the progress towards a fix and announcement.
*   We will coordinate with you on the public disclosure of the vulnerability after a fix is available.
*   If the reported issue is accepted, we will work on a fix.
*   If the reported issue is declined, we will provide a detailed explanation.

## Security Practices

This project aims to follow security best practices, including:

*   **Password Hashing:** Using strong hashing algorithms (PBKDF2 with salt via `crypto.pbkdf2Sync`).
*   **CSRF Protection:** Implementing the Synchronizer Token Pattern using the `csrf` library.
*   **Input Validation:** Using `express-validator` for validating and sanitizing user inputs on API endpoints.
*   **Rate Limiting:** Applying rate limits to API endpoints using `express-rate-limit` to mitigate brute-force attacks.
*   **Security Headers:** Utilizing `helmet` to set various security-related HTTP headers.
*   **Dependency Management:** Using `npm` for package management. We encourage users to regularly update dependencies and use tools like `npm audit` or GitHub's Dependabot.

## Scope

The scope of this security policy covers vulnerabilities found within the core codebase of the `nodejs-auth-starter` project itself. This generally **excludes**:

*   Vulnerabilities in third-party dependencies (please report those to the respective dependency's maintainers).
*   Security issues related to the specific deployment environment (server configuration, database security outside the schema, network configuration, etc.).
*   Vulnerabilities in code added or modified by users extending this starter template.
*   Issues related to MailHog or development-specific configurations.

## Acknowledgements

We value the contributions of security researchers. If you report a valid vulnerability that is fixed, we are happy to publicly acknowledge your contribution if you wish.
