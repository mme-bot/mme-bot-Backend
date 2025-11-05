package me.mmebot.auth.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.repository.EncryptionContextRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class EncryptionContextService {

    private final EncryptionContextRepository encryptionContextRepository;

    public EncryptionContext save(EncryptionContext encryptionContext) {
        return encryptionContextRepository.save(encryptionContext);
    }
}
