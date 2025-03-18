# Vulnerable Demo API

This project contains an intenttionally vulnerable REST API, created for educational purposes to demonstrate common security issues in APIs. It uses Flask and SQLAlchemy to provide a structure closed to that real-world projects.

## Warning

⚠️ **This code is INTENTIONALLY INSECURE and SHOULD NOT be used in production** ⚠️

This project is designed exclusively for educational and testing purposes, to help developers and security professionals understand and recognize common vulnerabilities in APIs.

## Demonstrated Vulnerabilities

This API includes the following vulnerabilities:

1. **User Enumeration via Login Responses**: The API reveals whether a user exists or not through specific error messages.
2. **User Enumeration via Forgot Password**: The password recovery route reveals if a user exists and exposes their email address.
3. **Accessing Unauthenticated Endpoints**: Endpoints that should require authentication are publicly accessible.
4. **JWT without verify permission**: Some endpoints do not properly verify user permissions.
5. **Rate Limiting**: Endpoints witout security control in place associated with Rate Limiting

## 🚀 Update - MFA & Password Reset Endpoints

### 🔹 New Endpoints Added

The following endpoints were added to demonstrate vulnerabilities in rate limiting:

1. **Generate MFA Code** (`POST /api/mfa/generate`)  
   - Generates a 6-digit MFA code for a user.  
   - **Vulnerability**: No rate limiting, allowing brute-force attacks to request multiple MFA codes.

2. **Verify MFA Code** (`POST /api/mfa/verify`)  
   - Verifies the MFA code provided by the user.  
   - **Vulnerability**: No rate limiting, enabling unlimited attempts to guess the MFA code.

3. **Reset Password** (`POST /api/reset-password`)  
   - Allows a user to reset their password via email.  
   - **Vulnerability**: No rate limiting, allowing brute-force enumeration of registered emails.

### 🔥 Security Issues Identified
- **Rate Limiting Missing**: Attackers can flood these endpoints with unlimited requests.
- **Brute-Force Risk**: No restrictions on MFA verification attempts.
- **User Enumeration**: Password reset endpoint confirms whether an email exists.

### 📌 Next Steps
To improve security, consider implementing:
- Rate limiting (e.g., Flask-Limiter).
- Locking mechanisms for excessive failed attempts.
- Secure MFA workflows with expiration and retry limits.

---

For more details, check the source code updates! 🛡️


## Requirements

- Python 3.6+
- Flask
- Flask-SQLAlchemy
- PyJWT
- Requests (para el script de pruebas)

## Installation

1. Clone this repository
2. Create a virutal environment (optional,but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```
3. Install the Dependencies:
   ```
   pip install flask flask-sqlalchemy pyjwt
   ```

## Execution

1. Start the API:
   ```
   python api_vulnerable.py
   ```
   The API will start at  `http://localhost:5000`

## Project Structure

- `api_vulnerable.py`: The vulnerable API implemented with Flask and SQLAlchemy.
- `exploits.py`: Script demonstrating how to exploit the vulnerabilities.
- `usuarios.db`: SQLite database created automatically with test users.

## Data Model

The application uses a simple `Usuario (User)` data model with the following fields:
- `id`: Unique identifier (integer).
- `username`: Username (unique).
- `password`: Password (stored as SHA-256 hash).
- `email`: User's email address.
- `is_admin`: Boolean indicating whether the user has admin privileges.

## API Routes

| Method | Route | Description | Vulnerability |
|--------|-------|-------------|---------------|
| POST   | `/api/login` | User Authentication | User enumeration |
| POST   | `/api/forgot-password` | Password recovery | User enumeration |
| GET    | `/api/users` | List all users | No authentication |
| GET    | `/api/admin/settings` | Admin settings | No permission verification |
| POST   | `/api/generate-mfa` | Generate MFA code | No rate limiting |
| POST   | `/api/verify-mfa` | Verify MFA code | No rate limiting |
| POST   | `/api/reset-password` | Reset password | No rate limiting |



## How to Protect Against These Vulnerabilities

### 1. User Enumeration

To avoid user enumeration:
- Use generic error messages like "Invalid credentials" instead of specifying whether the user exists or the password is incorrect.
- Use consistent response times to avoid timing attacks.

### 2. Unauthenticated Endpoints

- Implement authentication middleware for all routes that require protection.
- Use a role-based access control (RBAC) system.
- With SQLAlchemy, implement relationships that allow granular access control.


### 3. Best Practices with SQLAlchemy

- Use database migrations (e.g., with Alembic).
- Implement data validation at the model level.
- Use database sessions securely.
- Implement a permission system based on model relationships.

## License

This project is provided under the MIT License. See the LICENSE file for more details.

## Disclaimer

This code is for educational purposes only. Using this code to attack systems without explicit authorization is illegal and not endorsed by the author.
