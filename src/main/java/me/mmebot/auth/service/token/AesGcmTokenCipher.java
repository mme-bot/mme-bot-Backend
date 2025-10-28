package me.mmebot.auth.service.token;

import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.AesGcmEncryptor;
import me.mmebot.core.service.AesGcmEncryptor.EncryptionResult;
import me.mmebot.core.service.EncryptionContextFactory;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AesGcmTokenCipher implements TokenCipher {

    private final EncryptionContextFactory encryptionContextFactory;
    private final AesGcmEncryptor encryptor;

    @Override
    public EncryptedToken encrypt(String plainText, TokenCipherSpec spec) {
        Objects.requireNonNull(plainText, "plainText must not be null");
        TokenCipherSpec effectiveSpec = spec != null ? spec : TokenCipherSpec.empty();
        EncryptionContext context = createContext(effectiveSpec);
        EncryptionResult result = encryptor.encrypt(plainText, context, effectiveSpec.aad());
        context.updateTag(result.tag());
        log.debug("Encrypted token with context {}", context.getId());
        return new EncryptedToken(result.payload(), context);
    }

    @Override
    public String decrypt(EncryptedToken encryptedToken, TokenCipherSpec spec) {
        Objects.requireNonNull(encryptedToken, "encryptedToken must not be null");
        TokenCipherSpec effectiveSpec = spec != null ? spec : TokenCipherSpec.empty();
        try {
            String decrypted = encryptor.decrypt(encryptedToken.payload(), encryptedToken.context(),
                    effectiveSpec.aad());
            log.debug("Decrypted token with context {}", encryptedToken.context().getId());
            return decrypted;
        } catch (RuntimeException ex) {
            throw new TokenCipherException("Failed to decrypt token", ex);
        }
    }

    private EncryptionContext createContext(TokenCipherSpec spec) {
        byte[] aadHash = spec.aadHash();
        if (aadHash != null) {
            return encryptionContextFactory.createContext(aadHash);
        }
        return encryptionContextFactory.createContext();
    }
}
