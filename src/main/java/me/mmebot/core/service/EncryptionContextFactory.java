package me.mmebot.core.service;

import jakarta.transaction.Transactional;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.domain.EncryptionKey;
import me.mmebot.core.repository.EncryptionContextRepository;
import me.mmebot.core.repository.EncryptionKeyRepository;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class EncryptionContextFactory {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 32;
    private static final String ACTIVE_STATUS = "ACTIVE";

    private final EncryptionKeyRepository keyRepository;
    private final EncryptionContextRepository contextRepository;
    private final SecureRandom secureRandom;

    public EncryptionContextFactory(EncryptionKeyRepository keyRepository,
                                    EncryptionContextRepository contextRepository) {
        this.keyRepository = keyRepository;
        this.contextRepository = contextRepository;
        this.secureRandom = new SecureRandom();
    }

    public EncryptionContext createContext() {
        return createContext(null);
    }

    public EncryptionContext createContext(byte[] aadHash) {
        EncryptionKey key = keyRepository.findTopByStatusOrderByValidFromDesc(ACTIVE_STATUS)
                .orElseGet(this::createDefaultKey);

        EncryptionContext context = EncryptionContext.builder()
                .key(key)
                .iv(randomBytes(IV_LENGTH))
                .tag(randomBytes(TAG_LENGTH))
                .aadHash(aadHash)
                .encryptAt(OffsetDateTime.now())
                .build();

        return contextRepository.save(context);
    }

    private EncryptionKey createDefaultKey() {
        EncryptionKey key = EncryptionKey.builder()
                .alg("AES256-GCM")
                .validFrom(OffsetDateTime.now())
                .keyMaterial(randomBytes(KEY_LENGTH))
                .status(ACTIVE_STATUS)
                .build();
        return keyRepository.save(key);
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
