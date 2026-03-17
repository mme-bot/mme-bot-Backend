package me.mmebot.auth.service;

import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtTokenService;
import me.mmebot.auth.repository.AuthTokenRepository;
import me.mmebot.auth.repository.RoleRepository;
import me.mmebot.auth.security.CustomUserDetailsService;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.user.repository.UserRepository;
import me.mmebot.user.service.UserEmailProtector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private AuthTokenRepository authTokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtTokenService jwtTokenService;
    @Mock
    private TokenHashService tokenHashService;
    @Mock
    private EncryptionContextFactory encryptionContextFactory;
    @Mock
    private EmailVerificationService emailVerificationService;
    @Mock
    private RedisService redisService;
    @Mock
    private TokenCiperService tokenCiperService;
    @Mock
    private EncryptionContextService encryptionContextService;
    @Mock
    private CustomUserDetailsService customUserDetailsService;
    @Mock
    private UserEmailProtector userEmailProtector;

    @InjectMocks
    private AuthService authService;

    @Test
    void logoutRevokesRefreshToken() {
        Long userId = 10L;
        String refreshToken = "refresh-token";
        AuthToken authToken = AuthToken.builder()
                .id(88L)
                .type(AuthTokenType.REFRESH)
                .token("stored-token")
                .build();
        when(authTokenRepository.findByUserIdAndToken(userId, refreshToken))
                .thenReturn(Optional.of(authToken));

        authService.logout(userId, refreshToken);

        assertThat(authToken.isRevoked()).isTrue();
        verify(authTokenRepository).findByUserIdAndToken(userId, refreshToken);
    }

    @Test
    void logoutWithoutRefreshTokenThrowsException() {
        assertThatThrownBy(() -> authService.logout(5L, " "))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void logoutWithoutUserThrowsException() {
        assertThatThrownBy(() -> authService.logout(null, "token"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void logoutIgnoresMissingTokenRecord() {
        when(authTokenRepository.findByUserIdAndToken(3L, "missing"))
                .thenReturn(Optional.empty());

        assertThatCode(() -> authService.logout(3L, "missing"))
                .doesNotThrowAnyException();
    }
}
