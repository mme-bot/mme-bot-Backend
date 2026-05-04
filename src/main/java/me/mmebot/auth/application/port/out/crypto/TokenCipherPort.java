package me.mmebot.auth.application.port.out.crypto;

import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.core.domain.EncryptionContextEntity;

public interface TokenCipherPort {
    EncryptedToken encrypt(String token, Long userId);
    String decrypt(String token, EncryptionContextEntity context, AuthTokenType type, String aadSource);
}
