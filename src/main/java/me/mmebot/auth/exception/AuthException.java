package me.mmebot.auth.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class AuthException extends ApiException {

    private AuthException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static AuthException invalidCredentials() {
        return new AuthException(HttpStatus.NOT_FOUND, "Invalid credentials", "auth.invalid_credentials");
    }

    public static AuthException deletedAccount() {
        return new AuthException(HttpStatus.FORBIDDEN, "User account has been deleted", "auth.deleted_account");
    }

    public static AuthException duplicateEmail() {
        return new AuthException(HttpStatus.CONFLICT, "Email is already registered", "auth.duplicate_email");
    }

    public static AuthException refreshTokenUserMismatch() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Refresh token does not belong to the user", "auth.refresh_user_mismatch");
    }

    public static AuthException invalidTokenType() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Invalid token type", "auth.invalid_token_type");
    }

    public static AuthException userNotFound() {
        return new AuthException(HttpStatus.NOT_FOUND, "User not found", "auth.user_not_found");
    }

    public static AuthException refreshTokenMissing() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Refresh token is not registered", "auth.refresh_missing");
    }

    public static AuthException refreshTokenInvalid() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Refresh token is no longer valid", "auth.refresh_invalid");
    }

    public static AuthException tokenProcessingFailed(String message, Throwable cause) {
        AuthException exception = new AuthException(HttpStatus.BAD_REQUEST, message, "auth.token_processing_failed");
        if (cause != null) {
            exception.initCause(cause);
        }
        return exception;
    }

    public static AuthException emailRequired() {
        return new AuthException(HttpStatus.BAD_REQUEST, "Email must not be null", "auth.email_required");
    }
}
