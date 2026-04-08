package me.mmebot.auth.application.port.out;

import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.core.domain.EncryptionContext;

public interface TokenCipherPort {
    EncryptedToken encrypt(String token, Long userId);
    String decrypt(String token, EncryptionContext context, AuthTokenType type, String aadSource);
}
