package me.mmebot.auth.adapter.out.persistence;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.EncryptionContextPort;
import me.mmebot.auth.service.EncryptionContextService;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EncryptionContextAdapter implements EncryptionContextPort {

    private final EncryptionContextFactory encryptionContextFactory;
    private final EncryptionContextService encryptionContextService;

    @Override
    public EncryptionContext create(byte[] aadHash) {
        return encryptionContextFactory.createContext(aadHash);
    }

    @Override
    public EncryptionContext save(EncryptionContext context) {
        return encryptionContextService.save(context);
    }
}
