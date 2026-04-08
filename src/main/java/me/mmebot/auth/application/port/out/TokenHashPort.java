package me.mmebot.auth.application.port.out;

public interface TokenHashPort {
    byte[] hash(String value);
}
