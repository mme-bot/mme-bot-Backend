package me.mmebot.auth.application.port.out.persistence;

import me.mmebot.core.domain.EncryptionContextEntity;

public interface EncryptionContextPort {
    EncryptionContextEntity create(byte[] aadHash);
    EncryptionContextEntity save(EncryptionContextEntity context);
}
