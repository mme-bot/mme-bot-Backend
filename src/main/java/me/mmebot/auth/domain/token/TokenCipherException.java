package me.mmebot.auth.domain.token;

public class TokenCipherException extends RuntimeException {

    public TokenCipherException(String message) {
        super(message);
    }

    public TokenCipherException(String message, Throwable cause) {
        super(message, cause);
    }
}
