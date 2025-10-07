package me.mmebot.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

@Component
public class TokenHashService {

    private static final String HASH_ALGORITHM = "SHA-256";

    public byte[] hash(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Value to hash must not be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            return digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unable to initialize token hasher", ex);
        }
    }
}
