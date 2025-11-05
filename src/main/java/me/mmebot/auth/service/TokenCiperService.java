package me.mmebot.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.core.domain.EncryptionContext;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenCiperService {

    private final TokenHashService tokenHashService;
    private final TokenCipher tokenCipher;

    public EncryptedToken getEncryptedToken(String token,
                                             Long userId,
                                             byte[] aadHashOverride) {
        String tag = userId.toString();
        byte[] aadHash = aadHashOverride != null ? aadHashOverride : getAadHash(tag);
        return tokenCipher.encrypt(
                token,
                TokenCipherSpec.of(
                        getAad(tag),
                        aadHash
                )
        );
    }

    public String getDecodeToken(String token, EncryptionContext context, AuthTokenType type, String tag) {
        return tokenCipher.decrypt(asEncryptedToken(token, context, type.name()), TokenCipherSpec.of(getAad(tag), getAadHash(tag)));
    }

    private EncryptedToken asEncryptedToken(String payload,
                                            EncryptionContext context,
                                            String label) {
        if (payload == null || context == null) {
            throw new TokenCipherException("No encrypted " + label + " available");
        }
        return new EncryptedToken(payload, context);
    }


    private byte[] getAad(String tag) {
        return tag.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] getAadHash(String tag) {
        return tokenHashService.hash(tag);
    }
}
