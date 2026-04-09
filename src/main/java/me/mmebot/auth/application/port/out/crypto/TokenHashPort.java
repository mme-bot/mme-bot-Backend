package me.mmebot.auth.application.port.out.crypto;

public interface TokenHashPort {
    byte[] hash(String value);
}
