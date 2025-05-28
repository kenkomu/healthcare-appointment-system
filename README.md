# Healthcare Appointment System - Authentication Setup Guide

## Overview

This guide walks you through setting up Step 5: Authentication & Authorization for the Healthcare Appointment System. The implementation includes:

- ✅ JWT-based authentication
- ✅ Role-based access control (Patient, Doctor, Admin)
- ✅ OAuth 2.0 integration (Google)
- ✅ Password hashing and validation
- ✅ Refresh token mechanism
- ✅ Account lockout protection
- ✅ Password reset functionality

## Project Structure

Your current structure should look like this after implementation:

```
app/
├── __pycache__/
├── core/
│   ├── __init__.py
│   ├── config.py          # Configuration settings
│   ├── database.py        # Database connection setup
│   ├── security.py        # Authentication and security utilities
├── api/
│   ├── v1/
│   │   ├── auth.py        # Authentication endpoints
│   ├── deps.py            # Dependency injection for API routes
├── models/
│   ├── user.py            # User and refresh token database models
├── schemas/
│   ├── auth.py            # Authentication request/response models
├── services/
│   ├── auth_service.py    # Authentication business logic
├── main.py                # FastAPI application entry point
```

## Prerequisites

- Python 3.8+
- PostgreSQL database
- Redis server
- Google OAuth credentials (for social login)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/healthcare-appointment-system.git
   cd healthcare-appointment-system
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables by creating a `.env` file in the project root:
   ```
   # Application Settings
   APP_NAME=Healthcare Appointment System
   VERSION=1.0.0
   DEBUG=False

   # Database
   DATABASE_URL=postgresql://user:password@localhost:5432/healthcare_db

   # Security
   SECRET_KEY=your-super-secret-key-change-this-in-production-min-32-chars
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   REFRESH_TOKEN_EXPIRE_DAYS=7

   # OAuth 2.0 (Google)
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   OAUTH_REDIRECT_URI=http://localhost:8000/auth/callback

   # Redis
   REDIS_URL=redis://localhost:6379

   # Email (for password reset and notifications)
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password

   # CORS
   ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]
   ```

## Running the Application

1. Start your PostgreSQL database
2. Start your Redis server
3. Run the application:
   ```bash
   uvicorn app.main:app --reload
   ```

4. Access the API documentation at `http://localhost:8000/docs`

## Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/register` | POST | Register a new user |
| `/api/v1/auth/login` | POST | Authenticate and get access tokens |
| `/api/v1/auth/refresh` | POST | Refresh access token |
| `/api/v1/auth/logout` | POST | Logout (revoke refresh token) |
| `/api/v1/auth/me` | GET | Get current user information |
| `/api/v1/auth/change-password` | POST | Change password |
| `/api/v1/auth/forgot-password` | POST | Request password reset |
| `/api/v1/auth/reset-password` | POST | Reset password with token |
| `/api/v1/auth/oauth/google/login` | GET | Initialize Google OAuth login |
| `/api/v1/auth/oauth/callback` | POST | Handle OAuth callback |
| `/api/v1/auth/verify-token` | POST | Verify token validity |
| `/api/v1/auth/users` | GET | List users (admin only) |

## Testing

Run the authentication tests:

```bash
pytest tests/test_auth.py -v
```

## Security Features

### JWT Authentication
- Access tokens valid for 30 minutes by default
- Refresh tokens valid for 7 days by default
- Token revocation on logout and password change

### Password Security
- BCrypt password hashing
- Password strength validation
- Account lockout after 5 failed attempts
- Password reset functionality

### Role-Based Access Control
- Admin: Full access to all endpoints
- Doctor: Access to doctor-specific endpoints
- Patient: Access to patient-specific endpoints

### OAuth Integration
- Google sign-in supported
- CSRF protection with state parameter
- Automatic account creation for new OAuth users

## Notes for Production

- Change all default keys and secrets in the `.env` file
- Use a more secure database configuration
- Set up HTTPS with a proper certificate
- Configure proper email sending for password resets
- Set up a production-ready Redis instance with authentication# healthcare-appointment-system
