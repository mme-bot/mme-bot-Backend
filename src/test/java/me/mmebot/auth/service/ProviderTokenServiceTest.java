package me.mmebot.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.Optional;
import me.mmebot.auth.domain.ProviderToken;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.auth.exception.GoogleOAuthException;
import me.mmebot.auth.exception.ProviderTokenException;
import me.mmebot.auth.repository.ProviderTokenRepository;
import me.mmebot.common.mail.GoogleProperties;
import me.mmebot.common.mail.ProviderConstant;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.domain.EncryptionKey;
import me.mmebot.core.domain.EncryptionKeyStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ProviderTokenServiceTest {

    private static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String REDIRECT_URL = "https://mmebot.example.com/oauth2/callback";

    @Mock
    private ProviderTokenRepository providerTokenRepository;

    @Mock
    private TokenCipher tokenCipher;

    @Mock
    private TokenHashService tokenHashService;

    private GoogleProperties googleProperties;

    private ProviderTokenService providerTokenService;

    @BeforeEach
    void setUp() {
        googleProperties = new GoogleProperties(
                TOKEN_URL,
                true,
                "mmebot",
                "bot@example.com",
                "Mme Bot",
                " client-id ",
                "client-secret",
                null,
                REDIRECT_URL
        );
        providerTokenService = new ProviderTokenService(providerTokenRepository, tokenCipher, tokenHashService, googleProperties);
    }

    @Test
    void storeGoogleAuthorizationCode_trimsInputAndPersistsEncryptedToken() {
        byte[] aadHash = new byte[]{1, 2, 3};
        EncryptionContext context = sampleContext();

        when(providerTokenRepository.findByProviderAndClientId(ProviderConstant.GOOGLE, "client-id"))
                .thenReturn(Optional.empty());
        when(tokenHashService.hash("client-id")).thenReturn(aadHash);
        when(tokenCipher.encrypt(eq("CODE"), any(TokenCipherSpec.class)))
                .thenReturn(new EncryptedToken("encrypted-code", context));
        when(providerTokenRepository.save(any(ProviderToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        providerTokenService.storeGoogleAuthorizationCode("  CODE  ");

        verify(providerTokenRepository)
                .findByProviderAndClientId(ProviderConstant.GOOGLE, "client-id");
        verify(tokenHashService).hash("client-id");

        ArgumentCaptor<ProviderToken> tokenCaptor = ArgumentCaptor.forClass(ProviderToken.class);
        verify(providerTokenRepository).save(tokenCaptor.capture());
        ProviderToken saved = tokenCaptor.getValue();

        assertThat(saved.getProvider()).isEqualTo(ProviderConstant.GOOGLE);
        assertThat(saved.getClientId()).isEqualTo("client-id");
        assertThat(saved.getAuthorizationCode()).isEqualTo("encrypted-code");
        assertThat(saved.getAuthorizationCodeContext()).isSameAs(context);
    }

    @Test
    void storeGoogleAuthorizationCode_whenCodeBlank_throwsProviderTokenException() {
        assertThatThrownBy(() -> providerTokenService.storeGoogleAuthorizationCode("   "))
                .isInstanceOf(ProviderTokenException.class);

        verifyNoInteractions(providerTokenRepository, tokenHashService, tokenCipher);
    }

    @Test
    void storeGoogleAuthorizationCode_whenEncryptionFails_wrapsInGoogleOAuthException() {
        ProviderToken existing = ProviderToken.builder()
                .provider(ProviderConstant.GOOGLE)
                .clientId("client-id")
                .build();

        when(providerTokenRepository.findByProviderAndClientId(ProviderConstant.GOOGLE, "client-id"))
                .thenReturn(Optional.of(existing));
        when(tokenHashService.hash("client-id")).thenReturn(new byte[]{4});
        when(tokenCipher.encrypt(eq("CODE"), any(TokenCipherSpec.class)))
                .thenThrow(new TokenCipherException("boom"));

        assertThatThrownBy(() -> providerTokenService.storeGoogleAuthorizationCode("CODE"))
                .isInstanceOf(GoogleOAuthException.class);
    }

    @Test
    void storeGoogleAuthorizationCode_whenClientIdMissing_throwsProviderTokenException() {
        GoogleProperties invalidProperties = new GoogleProperties(
                TOKEN_URL,
                true,
                "mmebot",
                "bot@example.com",
                "Mme Bot",
                "   ",
                "client-secret",
                null,
                REDIRECT_URL
        );
        ProviderTokenService invalidService = new ProviderTokenService(
                providerTokenRepository,
                tokenCipher,
                tokenHashService,
                invalidProperties
        );

        assertThatThrownBy(() -> invalidService.storeGoogleAuthorizationCode("code"))
                .isInstanceOf(ProviderTokenException.class);

        verifyNoInteractions(providerTokenRepository, tokenHashService, tokenCipher);
    }

    @Test
    void getRefreshToken_returnsDecodedValue() {
        EncryptionContext context = sampleContext();
        ProviderToken stored = ProviderToken.builder()
                .provider(ProviderConstant.GOOGLE)
                .clientId("client-id")
                .refreshToken("encrypted-refresh")
                .refreshTokenContext(context)
                .build();

        when(providerTokenRepository.findByProviderAndClientId(ProviderConstant.GOOGLE, "client-id"))
                .thenReturn(Optional.of(stored));
        when(tokenHashService.hash("client-id")).thenReturn(new byte[]{9, 9});
        when(tokenCipher.decrypt(any(EncryptedToken.class), any(TokenCipherSpec.class)))
                .thenReturn("plain-refresh");

        String refreshToken = providerTokenService.getRefreshToken(ProviderConstant.GOOGLE);

        assertThat(refreshToken).isEqualTo("plain-refresh");
    }

    @Test
    void getRefreshToken_whenTokenMissing_throwsGoogleOAuthException() {
        when(providerTokenRepository.findByProviderAndClientId(ProviderConstant.GOOGLE, "client-id"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> providerTokenService.getRefreshToken(ProviderConstant.GOOGLE))
                .isInstanceOf(GoogleOAuthException.class);

        verify(tokenCipher, never()).decrypt(any(EncryptedToken.class), any(TokenCipherSpec.class));
    }

    @Test
    void getRefreshToken_whenClientIdMissing_throwsProviderTokenException() {
        GoogleProperties invalidProperties = new GoogleProperties(
                TOKEN_URL,
                true,
                "mmebot",
                "bot@example.com",
                "Mme Bot",
                null,
                "client-secret",
                null,
                REDIRECT_URL
        );
        ProviderTokenService invalidService = new ProviderTokenService(
                providerTokenRepository,
                tokenCipher,
                tokenHashService,
                invalidProperties
        );

        assertThatThrownBy(() -> invalidService.getRefreshToken(ProviderConstant.GOOGLE))
                .isInstanceOf(ProviderTokenException.class);

        verifyNoInteractions(providerTokenRepository, tokenHashService, tokenCipher);
    }

    private EncryptionContext sampleContext() {
        return EncryptionContext.builder()
                .id(1L)
                .iv(new byte[]{1})
                .tag(new byte[]{2})
                .aadHash(new byte[]{3})
                .key(EncryptionKey.builder()
                        .id(1L)
                        .alg("AES")
                        .validFrom(OffsetDateTime.now())
                        .keyMaterial(new byte[]{4})
                        .status(EncryptionKeyStatus.ACTIVE)
                        .build())
                .build();
    }
}
