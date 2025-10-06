package me.mmebot.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import me.mmebot.common.config.JwtProperties;
import org.springframework.stereotype.Component;

/**
 * Derives symmetric keys used for JWT signing and encryption from the configured secret.
 */
@Component
public class JwtKeyProvider {

    private static final String DIGEST_ALGORITHM = "SHA-256";

    private final byte[] cachedKey;

    public JwtKeyProvider(JwtProperties properties) {
        this.cachedKey = deriveKey(properties.secretKey());
    }

    public byte[] signingKey() {
        return Arrays.copyOf(cachedKey, cachedKey.length);
    }

    public byte[] encryptionKey() {
        return Arrays.copyOf(cachedKey, cachedKey.length);
    }

    private byte[] deriveKey(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT secret key must be configured");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
            return digest.digest(raw);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Unable to initialize JWT key derivation", ex);
        }
    }
}
