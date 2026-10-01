# auth-microservice

A lightweight, production-ready authentication microservice built with Flask and SQLite (easily swappable to PostgreSQL).

## Features

- **JWT-based access tokens** with refresh token rotation
- **Email verification** flow (SMTP integration ready)
- **Password reset** (forgot password endpoint)
- **PBKDF2 password hashing** (200k iterations)
- Stateless REST API — drop behind nginx/Caddy and you're done

## Quick Start

```bash
pip install -r requirements.txt
JWT_SECRET=your-secret python3 app.py
```

## API

| Method | Path                  | Description             |
|--------|-----------------------|-------------------------|
| POST   | /auth/signup          | Register new user       |
| POST   | /auth/verify          | Verify email with code  |
| POST   | /auth/login           | Login, get access token |
| GET    | /auth/me              | Current user info       |
| POST   | /auth/forgot-password | Request reset link      |

## Production Setup

- Replace SQLite with PostgreSQL via SQLAlchemy
- Configure SMTP for real email delivery
- Add rate limiting on login/signup endpoints
- Run behind a reverse proxy with HTTPS
