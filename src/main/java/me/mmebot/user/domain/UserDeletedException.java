package me.mmebot.user.domain;

public class UserDeletedException extends RuntimeException {

    public UserDeletedException(Long userId) {
        super("User %d is deleted".formatted(userId));
    }
}
