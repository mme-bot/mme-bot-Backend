package me.mmebot.auth.application.service;

import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.command.ClientMetadata;
import me.mmebot.auth.application.port.out.AccessTokenCachePort;
import me.mmebot.auth.application.port.out.EncryptionContextPort;
import me.mmebot.auth.application.port.out.JwtIssuePort;
import me.mmebot.auth.application.port.out.JwtParsePort;
import me.mmebot.auth.application.port.out.SaveRefreshTokenPort;
import me.mmebot.auth.application.port.out.TokenCipherPort;
import me.mmebot.auth.application.result.TokenPairResult;
import me.mmebot.auth.domain.AuthTokenEntity;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.user.domain.UserEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthTokenIssueSupport {

    private final JwtIssuePort jwtIssuePort;
    private final JwtParsePort jwtParsePort;
    private final TokenCipherPort tokenCipherPort;
    private final SaveRefreshTokenPort saveRefreshTokenPort;
    private final EncryptionContextPort encryptionContextPort;
    private final AccessTokenCachePort accessTokenCachePort;

    public TokenPairResult issue(UserEntity user, Collection<RoleName> roleNames, ClientMetadata clientMetadata) {
        Collection<RoleName> effectiveRoles = roleNames == null || roleNames.isEmpty()
                ? List.of(RoleName.ROLE_USER)
                : roleNames;

        Long userId = user.getId();

        String plainAccessToken = jwtIssuePort.createAccessToken(userId, effectiveRoles);
        String plainRefreshToken = jwtIssuePort.createRefreshToken(userId, effectiveRoles);

        AuthTokenEntity authToken = buildAndSaveRefreshToken(user, plainRefreshToken, clientMetadata);

        encryptAndCacheAccessToken(userId, plainAccessToken);

        log.debug("Issued tokens for user {} with roles {}", userId, effectiveRoles);
        return new TokenPairResult(plainAccessToken, authToken.getToken());
    }

    private AuthTokenEntity buildAndSaveRefreshToken(UserEntity user, String plainRefreshToken, ClientMetadata metadata) {
        JwtPayload payload = jwtParsePort.parse(plainRefreshToken);
        EncryptedToken encryptedRefresh = tokenCipherPort.encrypt(plainRefreshToken, user.getId());

        AuthTokenEntity authTokenEntity = new AuthTokenEntity(
                user,
                payload.tokenType(),
                encryptedRefresh.payload(),
                encryptedRefresh.context(),
                payload.expiresAt(),
                metadata != null ? metadata.ipAddress() : null,
                metadata != null ? metadata.userAgent() : null
        );

        AuthTokenEntity saved = saveRefreshTokenPort.save(authTokenEntity);
        log.debug("Stored refresh token for user {}", user.getId());
        return saved;
    }

    private void encryptAndCacheAccessToken(Long userId, String plainAccessToken) {
        EncryptedToken encryptedAccess = tokenCipherPort.encrypt(plainAccessToken, userId);
        encryptionContextPort.save(encryptedAccess.context());
        accessTokenCachePort.cache(userId, encryptedAccess.payload(), jwtIssuePort.accessTokenExpiry());
    }
}
