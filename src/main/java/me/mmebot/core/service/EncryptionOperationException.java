package me.mmebot.core.service;

public class EncryptionOperationException extends RuntimeException {

    public EncryptionOperationException(String message) {
        super(message);
    }

    public EncryptionOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
