package me.mmebot.auth.domain;

public class UnusableAuthTokenException extends RuntimeException {

    public UnusableAuthTokenException(Long tokenId) {
        super("Auth token %d is not usable".formatted(tokenId));
    }
}
