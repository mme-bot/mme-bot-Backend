package me.mmebot.auth.jwt;

class JwtProcessingException extends RuntimeException {

    JwtProcessingException(String message, Throwable cause) {
        super(message, cause);
    }

    JwtProcessingException(String message) {
        super(message);
    }
}
