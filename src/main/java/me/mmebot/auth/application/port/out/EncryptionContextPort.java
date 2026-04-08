package me.mmebot.auth.application.port.out;

import me.mmebot.core.domain.EncryptionContext;

public interface EncryptionContextPort {
    EncryptionContext create(byte[] aadHash);
    EncryptionContext save(EncryptionContext context);
}
