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
4. **JWT sin Verificación de Permisos**: Some endpoints do not properly verify user permissions.

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
| POST | `/api/login` | User Authentication | User enumeration |
| POST | `/api/forgot-password` | Password recovery | User enumeration |
| GET | `/api/users` | List all users | No authentication |
| GET | `/api/admin/settings` | Admin settings | No permission verification |


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
