package me.mmebot.auth.adapter.out.jwt;

import java.time.Duration;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.jwt.JwtIssuePort;
import me.mmebot.auth.application.port.out.jwt.JwtParsePort;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.auth.jwt.JwtProcessingException;
import me.mmebot.auth.jwt.JwtTokenService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenAdapter implements JwtIssuePort, JwtParsePort {

    private final JwtTokenService jwtTokenService;

    @Override
    public String createAccessToken(Long userId, Collection<RoleName> roles) {
        return jwtTokenService.createAccessToken(userId, roles);
    }

    @Override
    public String createRefreshToken(Long userId, Collection<RoleName> roles) {
        return jwtTokenService.createRefreshToken(userId, roles);
    }

    @Override
    public Duration accessTokenExpiry() {
        return jwtTokenService.getAccessTokenExpiry();
    }

    @Override
    public JwtPayload parse(String token) {
        try {
            return jwtTokenService.parse(token);
        } catch (JwtProcessingException ex) {
            throw AuthException.tokenProcessingFailed("Failed to process token", ex);
        }
    }
}
