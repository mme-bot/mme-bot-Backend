package me.mmebot.auth.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

public class GoogleOAuthException extends ApiException {
    protected GoogleOAuthException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static GoogleOAuthException failedGetRefreshToken(HttpStatusCode statusCode) {
        return new GoogleOAuthException(HttpStatus.valueOf(statusCode.value()), "Failed to retrieve token", "google_oauth.failed_get_refresh_token");
    }

    public static GoogleOAuthException requestFailed() {
        return new GoogleOAuthException(HttpStatus.INTERNAL_SERVER_ERROR, "Google OAuth Token Request Failed", "google_oauth.request_failed");
    }
}
