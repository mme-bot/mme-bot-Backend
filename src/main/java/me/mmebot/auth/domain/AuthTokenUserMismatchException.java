package me.mmebot.auth.domain;

public class AuthTokenUserMismatchException extends RuntimeException {

    public AuthTokenUserMismatchException(Long tokenId, Long expectedUserId, Long actualUserId) {
        super("Auth token %d user mismatch: expected %s, actual %s"
                .formatted(tokenId, expectedUserId, actualUserId));
    }
}
