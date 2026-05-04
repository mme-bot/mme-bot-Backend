package me.mmebot.auth.domain;

public class InvalidAuthTokenTypeException extends RuntimeException {

    public InvalidAuthTokenTypeException(Long tokenId, AuthTokenType actualType) {
        super("Auth token %d has invalid type %s".formatted(tokenId, actualType));
    }
}
