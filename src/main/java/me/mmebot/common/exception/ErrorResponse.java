package me.mmebot.common.exception;

import java.time.OffsetDateTime;

public record ErrorResponse(
        OffsetDateTime timestamp,
        int status,
        String error,
        String message,
        String code,
        String path
) {
    public static ErrorResponse of(int status, String error, String message, String code, String path) {
        return new ErrorResponse(OffsetDateTime.now(), status, error, message, code, path);
    }
}
