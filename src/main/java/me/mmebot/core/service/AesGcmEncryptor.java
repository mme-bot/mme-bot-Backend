package me.mmebot.core.service;

import jakarta.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.core.config.EncryptionKeyProperties;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.domain.EncryptionKey;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AesGcmEncryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";

    private final int authenticationTagSize;

    public AesGcmEncryptor(EncryptionKeyProperties properties) {
        this.authenticationTagSize = Objects.requireNonNull(properties.length(), "encryptionKeyLength must not be null")
                .tag();
    }

    public EncryptionResult encrypt(String plainText, EncryptionContext context, @Nullable byte[] additionalData) {
        Objects.requireNonNull(plainText, "plainText must not be null");
        Objects.requireNonNull(context, "context must not be null");

        try {
            EncryptionKey key = context.getKey();
            if (key == null || key.getKeyMaterial() == null) {
                throw new EncryptionOperationException("Encryption key material is missing");
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKey = new SecretKeySpec(key.getKeyMaterial(), KEY_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(authenticationTagSize * Byte.SIZE, context.getIv());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            if (additionalData != null && additionalData.length > 0) {
                cipher.updateAAD(additionalData);
            }
            byte[] cipherBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            if (cipherBytes.length < authenticationTagSize) {
                throw new EncryptionOperationException("Ciphertext shorter than authentication tag");
            }
            byte[] tag = Arrays.copyOfRange(cipherBytes, cipherBytes.length - authenticationTagSize, cipherBytes.length);
            String payload = Base64.getEncoder().encodeToString(cipherBytes);
            log.debug("Successfully encrypted payload using AES/GCM");
            return new EncryptionResult(payload, tag);
        } catch (GeneralSecurityException ex) {
            throw new EncryptionOperationException("Failed to encrypt value using AES/GCM", ex);
        }
    }

    public record EncryptionResult(String payload, byte[] tag) {
    }
}
