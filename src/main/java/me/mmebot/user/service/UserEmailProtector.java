package me.mmebot.user.service;

import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.service.TokenHashService;
import me.mmebot.common.crypto.AesGcmCryptoService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserEmailProtector {

    private final TokenHashService tokenHashService;
    private final AesGcmCryptoService aesGcmCryptoService;
    private final PasswordEncoder passwordEncoder;

    public EmailSecrets prepare(String normalizedEmail) {
        return prepare(normalizedEmail, null);
    }

    public EmailSecrets prepare(String normalizedEmail, byte[] precomputedHash) {
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank");
        }
        byte[] aadHash = precomputedHash != null ? Arrays.copyOf(precomputedHash, precomputedHash.length)
                : tokenHashService.hash(normalizedEmail);
        String emailCipher = aesGcmCryptoService.encryptWithAad(normalizedEmail, aadHash);
        String emailHash = passwordEncoder.encode(normalizedEmail);
        return new EmailSecrets(emailCipher, emailHash, aadHash);
    }

    public byte[] aadHash(String normalizedEmail) {
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank");
        }
        return tokenHashService.hash(normalizedEmail);
    }

    public record EmailSecrets(String emailCipher, String emailHash, byte[] aadHash) {
        public EmailSecrets {
            aadHash = aadHash != null ? Arrays.copyOf(aadHash, aadHash.length) : null;
        }
    }
}
