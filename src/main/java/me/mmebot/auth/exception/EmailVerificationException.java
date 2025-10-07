package me.mmebot.auth.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class EmailVerificationException extends ApiException {

    private EmailVerificationException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static EmailVerificationException invalidEmailFormat() {
        return new EmailVerificationException(HttpStatus.NOT_FOUND, "Invalid email format", "email.invalid_format");
    }

    public static EmailVerificationException rateLimited() {
        return new EmailVerificationException(HttpStatus.TOO_MANY_REQUESTS, "Verification request limit exceeded", "email.rate_limited");
    }

    public static EmailVerificationException notFound() {
        return new EmailVerificationException(HttpStatus.NOT_FOUND, "Email verification not found", "email.not_found");
    }

    public static EmailVerificationException expired() {
        return new EmailVerificationException(HttpStatus.GONE, "Verification code expired", "email.expired");
    }

    public static EmailVerificationException codeMismatch() {
        return new EmailVerificationException(HttpStatus.BAD_REQUEST, "Verification code mismatch", "email.code_mismatch");
    }

    public static EmailVerificationException notVerified() {
        return new EmailVerificationException(HttpStatus.FORBIDDEN, "Email verification not completed", "email.not_verified");
    }

    public static EmailVerificationException emailMismatch() {
        return new EmailVerificationException(HttpStatus.FORBIDDEN, "Email does not match verification record", "email.email_mismatch");
    }

    public static EmailVerificationException emailRequired() {
        return new EmailVerificationException(HttpStatus.NOT_FOUND, "Email must not be null", "email.email_required");
    }
}
