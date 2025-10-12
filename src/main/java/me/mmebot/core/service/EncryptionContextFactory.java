package me.mmebot.core.service;

import jakarta.transaction.Transactional;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.core.config.EncryptionKeyProperties;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.domain.EncryptionKey;
import me.mmebot.core.domain.EncryptionKeyStatus;
import me.mmebot.core.repository.EncryptionContextRepository;
import me.mmebot.core.repository.EncryptionKeyRepository;
import org.springframework.stereotype.Service;

@Service
@Transactional
@Slf4j
public class EncryptionContextFactory {

    private static final EncryptionKeyStatus ACTIVE_STATUS = EncryptionKeyStatus.ACTIVE;

    private final EncryptionKeyRepository keyRepository;
    private final EncryptionContextRepository contextRepository;
    private final EncryptionKeyProperties keyProperties;
    private final EncryptionKeyProperties.Length keyLengths;
    private final SecureRandom secureRandom;

    public EncryptionContextFactory(EncryptionKeyRepository keyRepository,
                                    EncryptionContextRepository contextRepository,
                                    EncryptionKeyProperties keyProperties) {
        this.keyRepository = keyRepository;
        this.contextRepository = contextRepository;
        this.keyProperties = Objects.requireNonNull(keyProperties, "encryptionKeyProperties must not be null");
        this.keyLengths = Objects.requireNonNull(keyProperties.length(), "encryptionKeyLengths must not be null");
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
                .iv(randomBytes(keyLengths.iv()))
                .tag(randomBytes(keyLengths.tag()))
                .aadHash(aadHash)
                .encryptAt(OffsetDateTime.now())
                .build();

        EncryptionContext saved = contextRepository.save(context);
        log.debug("Created encryption context {} using key {}", saved.getId(), key.getId());
        return saved;
    }

    private EncryptionKey createDefaultKey() {
        EncryptionKey key = EncryptionKey.builder()
                .alg(keyProperties.algorithm())
                .validFrom(OffsetDateTime.now())
                .keyMaterial(randomBytes(keyLengths.key()))
                .status(ACTIVE_STATUS)
                .build();
        EncryptionKey saved = keyRepository.save(key);
        log.info("Generated default ACTIVE encryption key {}", saved.getId());
        return saved;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
