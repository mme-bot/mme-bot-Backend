package me.mmebot.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TokenHashService {

    private static final String HASH_ALGORITHM = "SHA-256";

    public byte[] hash(String value) {
        if (value == null) {
            log.error("Token hashing failed: value must not be null");
            throw new IllegalArgumentException("Value to hash must not be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            log.debug("Token hashing succeeded using {}", HASH_ALGORITHM);
            return hashed;
        } catch (NoSuchAlgorithmException ex) {
            log.error("Token hashing failed: algorithm {} not available", HASH_ALGORITHM, ex);
            throw new IllegalStateException("Unable to initialize token hasher", ex);
        }
    }
}
