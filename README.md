# tvbingefriend-user-service

Service to manage and access user data in TVBingeFriend.

## API Documentation

This service includes interactive Swagger/OpenAPI documentation for all endpoints.

### Accessing the Documentation

1. Start the service:
   ```bash
   go run .
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:8080/swagger/index.html
   ```

### Generating Documentation

After making changes to API annotations, regenerate the docs:

```bash
swag init
```

Or if `swag` is not in your PATH:

```bash
~/go/bin/swag init
```

### API Endpoints Overview

**Authentication:**
- `POST /register` - Register a new user
- `POST /login` - Login user
- `GET /verify` - Verify JWT token
- `POST /refresh` - Refresh access token

**Email Verification:**
- `GET /verify-email` - Verify email address
- `POST /resend-verification` - Resend verification email

**Password Reset:**
- `POST /request-password-reset` - Request password reset
- `POST /reset-password` - Reset password with token

**Account Management:**
- `DELETE /delete-account` - Delete user account

**Profile Management:**
- `GET /profile` - Get user profile
- `PUT /profile/username` - Update username
- `PUT /profile/email` - Update email
- `PUT /profile/password` - Change password

**System:**
- `GET /health` - Health check

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.