package me.mmebot.auth.adapter.out.crypto;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.TokenCipherPort;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.service.TokenCiperService;
import me.mmebot.core.domain.EncryptionContextEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenCipherAdapter implements TokenCipherPort {

    private final TokenCiperService tokenCiperService;

    @Override
    public EncryptedToken encrypt(String token, Long userId) {
        return tokenCiperService.getEncryptedToken(token, userId, null);
    }

    @Override
    public String decrypt(String token, EncryptionContextEntity context, AuthTokenType type, String aadSource) {
        return tokenCiperService.getDecodeToken(token, context, type, aadSource);
    }
}
