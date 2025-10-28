package me.mmebot.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.auth.service.TokenHashService;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.domain.EncryptionKey;
import me.mmebot.core.domain.EncryptionKeyStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ProviderTokenTest {

    @Mock
    private TokenCipher tokenCipher;

    @Mock
    private TokenHashService tokenHashService;

    @Test
    void storeRefreshToken_overwritesTokensAndResetsFlags() {
        ProviderToken token = ProviderToken.builder()
                .provider("GOOGLE")
                .clientId("client-id")
                .authorizationCode("old-code")
                .authorizationCodeContext(sampleContext())
                .active(false)
                .errorCount(3)
                .build();

        EncryptionContext context = sampleContext();
        when(tokenHashService.hash("client-id")).thenReturn(new byte[]{1, 2});
        when(tokenCipher.encrypt(eq("refresh"), any(TokenCipherSpec.class)))
                .thenReturn(new EncryptedToken("encrypted-refresh", context));

        token.storeRefreshToken("refresh", tokenCipher, tokenHashService);

        verify(tokenHashService).hash("client-id");
        assertThat(token.getRefreshToken()).isEqualTo("encrypted-refresh");
        assertThat(token.getRefreshTokenContext()).isSameAs(context);
        assertThat(token.getAuthorizationCode()).isNull();
        assertThat(token.getAuthorizationCodeContext()).isNull();
        assertThat(token.isActive()).isTrue();
        assertThat(token.getErrorCount()).isZero();
        assertThat(token.hasRefreshToken()).isTrue();
    }

    @Test
    void storeAccessToken_persistsEncryptedTokenMetadata() {
        ProviderToken token = ProviderToken.builder()
                .provider("GOOGLE")
                .clientId("client-id")
                .tokenType("Bearer")
                .errorCount(5)
                .active(false)
                .build();

        OffsetDateTime refreshedAt = OffsetDateTime.now();
        OffsetDateTime expiresAt = refreshedAt.plusSeconds(3600);
        EncryptionContext context = sampleContext();
        byte[] aadHash = new byte[]{3, 3, 3};

        when(tokenHashService.hash("client-id")).thenReturn(aadHash);
        when(tokenCipher.encrypt(eq("access"), any(TokenCipherSpec.class)))
                .thenReturn(new EncryptedToken("encrypted-access", context));

        token.storeAccessToken("access", expiresAt, "Custom", "mail.read", refreshedAt, tokenHashService, tokenCipher);

        verify(tokenHashService).hash("client-id");
        assertThat(token.getAccessToken()).isEqualTo("encrypted-access");
        assertThat(token.getAccessTokenContext()).isSameAs(context);
        assertThat(token.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(token.getTokenType()).isEqualTo("Custom");
        assertThat(token.getScopes()).isEqualTo("mail.read");
        assertThat(token.getLastRefreshAt()).isEqualTo(refreshedAt);
        assertThat(token.isActive()).isTrue();
        assertThat(token.getErrorCount()).isZero();
        assertThat(token.hasAccessToken()).isTrue();
    }

    @Test
    void getDecodeRefreshToken_usesClientSpecificParameters() {
        EncryptionContext context = sampleContext();
        ProviderToken token = ProviderToken.builder()
                .provider("GOOGLE")
                .clientId("client-id")
                .refreshToken("encrypted-refresh")
                .refreshTokenContext(context)
                .build();

        byte[] aadHash = new byte[]{5, 5};
        when(tokenHashService.hash("client-id")).thenReturn(aadHash);
        when(tokenCipher.decrypt(any(EncryptedToken.class), any(TokenCipherSpec.class)))
                .thenReturn("plain-refresh");

        String result = token.getDecodeRefreshToken(tokenCipher, tokenHashService);

        assertThat(result).isEqualTo("plain-refresh");

        ArgumentCaptor<TokenCipherSpec> specCaptor = ArgumentCaptor.forClass(TokenCipherSpec.class);
        verify(tokenCipher).decrypt(any(EncryptedToken.class), specCaptor.capture());

        TokenCipherSpec spec = specCaptor.getValue();
        byte[] expectedAad = "client-id".getBytes(StandardCharsets.UTF_8);
        assertThat(spec.aad()).containsExactly(expectedAad);
        assertThat(spec.aadHash()).containsExactly(aadHash);
    }

    @Test
    void getDecodeRefreshToken_whenMissingEncryptedContext_throwsTokenCipherException() {
        ProviderToken token = ProviderToken.builder()
                .provider("GOOGLE")
                .clientId("client-id")
                .refreshToken(null)
                .refreshTokenContext(null)
                .build();

        assertThatThrownBy(() -> token.getDecodeRefreshToken(tokenCipher, tokenHashService))
                .isInstanceOf(TokenCipherException.class);
    }

    private EncryptionContext sampleContext() {
        return EncryptionContext.builder()
                .id(1L)
                .iv(new byte[]{1})
                .tag(new byte[]{2})
                .aadHash(new byte[]{3})
                .key(EncryptionKey.builder()
                        .id(2L)
                        .alg("AES")
                        .validFrom(OffsetDateTime.now())
                        .keyMaterial(new byte[]{5})
                        .status(EncryptionKeyStatus.ACTIVE)
                        .build())
                .build();
    }
}
