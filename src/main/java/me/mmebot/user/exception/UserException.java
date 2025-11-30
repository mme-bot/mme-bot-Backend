package me.mmebot.user.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class UserException extends ApiException {

    protected UserException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static UserException userNotFound(Long userId) {
        return new UserException(HttpStatus.NOT_FOUND,
                "User %d not found".formatted(userId),
                "diary.user_not_found");
    }

    public static UserException userDeleted(Long userId) {
        return new UserException(HttpStatus.FORBIDDEN,
                "User %d is deleted".formatted(userId),
                "diary.user_deleted");
    }
}
