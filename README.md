# SparkAuth SSO Login Provider

A self-hosted OIDC (OpenID Connect) identity provider built with Go, Gin, and PostgreSQL. 

## Goals
- easy to install/setup and use
- just the things I need for mentorsparks.com SSO 


## Features

- **OIDC Provider**: Full OpenID Connect authorization code flow with PKCE support
- **Email Magic Link**: Passwordless sign-in via email
- **GitHub OAuth**: Sign in with GitHub
- **Admin Dashboard**: Manage applications, users, and settings
- **Glass Morphism UI**: Dark theme with modern design

## Screenshots

![Login Page](screenshots/sparkauth3.png)

*Login page with email magic link option.*

![Admin](screenshots/sparkauth.png)

*Admin page*


![Admin Dashboard](screenshots/sparkauth2.png)

*Admin dashboard for managing users and applications.*

## Quick Start

### Prerequisites
- Go 1.23+
- PostgreSQL

### Setup

1. Create the database:
   ```sql
   CREATE DATABASE sparkauth;
   ```

2. Copy and configure environment (for database and basic settings):
   ```bash
   cp .env.example .env
   # Edit .env with your database URL, issuer URL, port, and initial admin email
   ```

3. Run:
   ```bash
   go mod tidy
   go run .
   ```

4. **First Login**: Open http://localhost:9000/admin. The app will prompt for login. Enter the admin email from your `.env` file. A magic link will be printed to the console (since SMTP is not yet configured). Copy and paste the link into your browser to log in.

5. Once logged in, go to Admin → Settings to configure email (SMTP) and GitHub OAuth via the web UI. These settings are stored in the database and take precedence over environment variables.

### Running with Docker Compose

If you prefer using Docker:

1. Ensure Docker and Docker Compose are installed.

2. Copy and configure environment (optional, for database and basic settings):
   ```bash
   cp .env.example .env
   # Edit .env with your database URL, issuer URL, port, and initial admin email
   ```

3. Run:
   ```bash
   docker compose up
   ```

4. **First Login**: Open http://localhost:9000/admin. Enter the admin email from your `.env` file. A magic link will be logged to the console (SMTP not configured yet). Use the link to log in.

5. Configure email and OAuth settings through the Admin UI (stored in database).

The database will be automatically created and configured. Settings like email and OAuth are managed via the database through the admin interface, not environment variables.

## Configuration

SparkAuth uses a database-driven configuration system. After initial setup:

- **Database Connection**: Set via `DATABASE_URL` in `.env`
- **Basic Settings**: Issuer URL, port, session secret, and initial admin email via `.env`
- **Feature Settings**: Email (SMTP), GitHub OAuth, and feature toggles are configured through the Admin UI and stored in the database. These override any environment variables.

Environment variables serve as fallbacks for basic setup, but all operational settings (SMTP, OAuth credentials, enabled features) are managed in the database via `/admin/settings`.

## First Login Process

1. Start the application with a configured admin email in `.env` (e.g., `ADMIN_EMAIL=admin@example.com`).
2. Navigate to `/admin`.
3. Enter the admin email and submit.
4. The app generates a magic link and logs it to the console (since SMTP is not yet configured).
5. Copy the logged URL (e.g., `http://localhost:9000/login/verify?token=...`) and paste it into your browser.
6. This completes login and grants admin access.
7. Configure SMTP in Admin → Settings to enable email-based magic links for users.

## OIDC Endpoints

| Endpoint | URL |
|----------|-----|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/authorize` |
| Token | `/token` |
| UserInfo | `/userinfo` |
| JWKS | `/jwks` |

## Registering an Application

1. Log in as admin and go to Admin → Applications → New Application
2. Set a name and redirect URI(s)
3. Copy the Client ID and Client Secret
4. Configure your app with:
   - **Issuer**: Your configured issuer URL (from `.env` or database)
   - **Client ID**: from step 3
   - **Client Secret**: from step 3
   - **Redirect URI**: must match one registered

Note: All application and user management is done through the admin dashboard. Feature settings (email, OAuth) are configured in Admin → Settings.
   - **Scopes**: `openid profile email`



## Planned features
- Email templates (per application)
- multitenacy



## Used at
- https://mentorsparks.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
