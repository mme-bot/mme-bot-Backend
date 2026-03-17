package me.mmebot.auth.api;

import java.time.Duration;
import me.mmebot.auth.api.dto.LogoutRequest;
import me.mmebot.auth.service.AuthService;
import me.mmebot.auth.service.EmailVerificationService;
import me.mmebot.common.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;
    @Mock
    private EmailVerificationService emailVerificationService;

    private AuthController authController;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = new JwtProperties(
                "kid",
                "issuer",
                "secret",
                Duration.ofMinutes(5),
                Duration.ofDays(1)
        );
        authController = new AuthController(authService, emailVerificationService, jwtProperties);
    }

    @Test
    void logoutClearsAccessTokenCookieAndRevokesRefreshToken() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        authController.logout(42L, new LogoutRequest("refresh-token"), response);

        verify(authService).logout(42L, "refresh-token");
        String cookie = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(cookie)
                .isNotBlank()
                .contains("access_token=")
                .contains("Max-Age=0")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
    }
}
