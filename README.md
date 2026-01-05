# Introduction to Computer Security – Auth Service

A FastAPI-based authentication service that demonstrates common hardening techniques for login flows. The project showcases password hashing (SHA-256 with salt, bcrypt, Argon2id), peppering, rate limiting, user lockout, CAPTCHA challenges, time-based one-time passwords (TOTP), and structured logging for authentication attempts.

## Features

- **Multiple hashing strategies:** Select SHA-256, bcrypt, or Argon2id at runtime.
- **Defense in depth:** Rate limiting, user lockout, CAPTCHA enforcement, TOTP verification, and optional password peppering are all configurable.
- **Audit-friendly logging:** Every login attempt is recorded to `attempts.log` with timing, protection flags, and outcomes. 【loggers/attempts_logger.py†L1-L36】
- **SQLite-backed user store:** SQLModel models backed by a local SQLite database created automatically on startup. 【db_manager.py†L10-L38】

## Project layout

- `main.py` – FastAPI entrypoint exposing auth endpoints.
- `context.py` – Central dependency container wiring settings, DB access, hashing, protections, and gateways.
- `models/` – Pydantic request payloads and SQLModel ORM entities.
- `extra_protections/` – Rate limiting, lockout tracking, CAPTCHA management, peppering, and TOTP utilities.
- `hashing/` – Hashing implementations and selector for the active algorithm.
- `loggers/` – Base logger configuration plus authentication-attempt logging.
- `attempts/` – Sample log outputs for attack simulations.

## Getting started

### Prerequisites

- Python 3.11+ (recommended)
- SQLite (bundled with Python)

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration

Runtime options are loaded from environment variables (or a `.env` file at `config/.env`). Defaults shown below match `settings/settings.py`:

| Variable | Default | Description                                              |
| --- | --- |----------------------------------------------------------|
| `HASH_MODE` | `sha256` | Active password hasher (`argon2id`, `bcrypt`, `sha256`). |
| `RATE_LIMIT_ENABLED` | `true` | Enable per-user request limiting.                        |
| `USER_LOCKOUT_ENABLED` | `true` | Lock accounts after repeated failures.                   |
| `CAPTCHA_ENABLED` | `true` | Require CAPTCHA after too many misses.                   |
| `TOTP_ENABLED` | `true` | Enforce second factor on login.                          |
| `PEPPER_ENABLED` | `true` | Append a server-side pepper to passwords.                |
| `PEPPER_VALUE` | _unset_ | Pepper string applied when `PEPPER_ENABLED` is true.     |
| `SEED_GROUP` | `0x039C76D` | team's seed group.                                       |

Create the `config/.env` file as needed:

```bash
mkdir -p config
cat <<'EOF' > config/.env
HASH_MODE=argon2id
RATE_LIMIT_ENABLED=true
USER_LOCKOUT_ENABLED=true
CAPTCHA_ENABLED=true
TOTP_ENABLED=true
PEPPER_ENABLED=true
PEPPER_VALUE=replace-with-a-secret
SEED_GROUP=0x039C76D
EOF
```

### Running the API

```bash
uvicorn server.main:app --reload
```

SQLite data is stored in `data.db` at the repository rooty

## API overview

| Method & Path | Purpose | Notes |
| --- | --- | --- |
| `GET /` | Health check | Returns a simple greeting. |
| `POST /register` | Create a new user | Stores hashes for all algorithms and a fresh TOTP secret.
| `POST /login` | Password verification | Honors the active hash mode, rate limiting, lockout, CAPTCHA, and pepper. On success with TOTP enabled, returns a prompt to supply a code.
| `POST /login_totp` | TOTP verification | Confirms a TOTP code for a user and updates the last verification timestamp. 【main.py†L115-L133】 |
| `GET /admin/get_captcha_token` | Issue a CAPTCHA token | Requires a matching `group_seed` query parameter. Pass the returned token via `X-CAPTCHA-TOKEN` header on `/login`.
| `DELETE /users/{username}` | Remove a user | Useful for cleaning up seeded accounts between runs

Example login call with a CAPTCHA token:

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "X-CAPTCHA-TOKEN: <token-from-get_captcha_token>" \
  -d '{"username": "alice", "password": "correct horse battery staple"}'
```

## Protections in detail

- **Rate limiting:** Caps login attempts per user within a sliding window to deter brute force.
- **User lockout:** Permanently locks accounts after repeated failures.
- **CAPTCHA escalation:** Issues one-time tokens after excessive failures; invalid or missing tokens raise `403`.
- **TOTP second factor:** Generates secrets per user and validates codes while preventing reuse in the same time step.
- **Peppering:** Optionally appends a server-side secret to passwords before hashing.

## Seeding users for local testing

The API does not ship with preloaded users. To mirror the sample login tests, register a user such as `weak_password_user_1` with password `123456` before hitting `/login` or `/login_totp`. The TOTP secret returned by `/register` (or stored in the database) can be used to generate codes via `TOTPManager.generate_current_code`.

## Logging

Login attempts are serialized as JSON lines to `attempts.log` and include timestamp, username, enabled protections, outcome, and request latency. You can adjust the base logger behavior in `loggers/logger.py`.

## Running tests

Pytest is configured for the FastAPI app:

```bash
pytest
```

Ensure any referenced users (e.g., `weak_password_user_1`) exist in the database before executing the suite.