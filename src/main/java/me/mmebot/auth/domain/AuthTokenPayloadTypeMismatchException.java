package me.mmebot.auth.domain;

public class AuthTokenPayloadTypeMismatchException extends RuntimeException {

    public AuthTokenPayloadTypeMismatchException(Long tokenId,
                                                 AuthTokenType expectedType,
                                                 AuthTokenType actualType) {
        super("Auth token %d payload type mismatch: expected %s, actual %s"
                .formatted(tokenId, expectedType, actualType));
    }
}
