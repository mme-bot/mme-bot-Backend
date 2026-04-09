package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.command.ReissueTokenCommand;
import me.mmebot.auth.application.port.in.ReissueTokenUseCase;
import me.mmebot.auth.application.port.out.JwtParsePort;
import me.mmebot.auth.application.port.out.LoadRefreshTokenPort;
import me.mmebot.auth.application.port.out.LoadUserPort;
import me.mmebot.auth.application.port.out.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.SaveRefreshTokenPort;
import me.mmebot.auth.application.port.out.TokenCipherPort;
import me.mmebot.auth.application.port.out.TokenHashPort;
import me.mmebot.auth.application.result.TokenPairResult;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class ReissueTokenService implements ReissueTokenUseCase {

    private final LoadUserPort loadUserPort;
    private final LoadRefreshTokenPort loadRefreshTokenPort;
    private final SaveRefreshTokenPort saveRefreshTokenPort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final TokenHashPort tokenHashPort;
    private final TokenCipherPort tokenCipherPort;
    private final JwtParsePort jwtParsePort;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public TokenPairResult reissue(ReissueTokenCommand command) {
        User user = loadUserPort.loadById(command.userId())
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: user {} not found", command.userId());
                    return AuthException.userNotFound();
                });

        if (user.isDeleted()) {
            log.warn("Token reissue failed: user {} is marked as deleted", command.userId());
            throw AuthException.deletedAccount();
        }

        AuthToken authToken = loadRefreshTokenPort
                .loadByUserIdAndToken(command.userId(), command.refreshToken())
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: token not found for user {}", command.userId());
                    return AuthException.tokenNotFound();
                });

        if (!authToken.getType().equals(AuthTokenType.REFRESH)) {
            log.warn("Token reissue failed: token {} is not a refresh token", authToken.getId());
            throw AuthException.refreshTokenMissing();
        }

        OffsetDateTime now = OffsetDateTime.now();
        if (authToken.isRevoked() || authToken.isExpired(now)) {
            log.warn("Token reissue failed: refresh token invalid for user {}", command.userId());
            throw AuthException.refreshTokenInvalid();
        }

        byte[] userHash = tokenHashPort.hash(command.userId().toString());
        if (!Arrays.equals(userHash, authToken.getEncryptionContext().getAadHash())) {
            log.warn("Token reissue failed: aad hash mismatch for user {}", command.userId());
            authToken.revoke(now);
            saveRefreshTokenPort.save(authToken);
            throw AuthException.refreshTokenInvalid();
        }

        String decryptedToken = tokenCipherPort.decrypt(
                authToken.getToken(),
                authToken.getEncryptionContext(),
                authToken.getType(),
                command.userId().toString()
        );

        JwtPayload payload = jwtParsePort.parse(decryptedToken);

        if (!Objects.equals(payload.userId(), command.userId())) {
            log.warn("Token reissue failed: payload user mismatch (expected {}, got {})",
                    command.userId(), payload.userId());
            authToken.revoke(now);
            saveRefreshTokenPort.save(authToken);
            throw AuthException.refreshTokenUserMismatch();
        }

        if (payload.tokenType() != AuthTokenType.REFRESH) {
            log.warn("Token reissue failed: invalid token type {} for user {}",
                    payload.tokenType(), command.userId());
            throw AuthException.invalidTokenType();
        }

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(command.userId());
        log.info("Token reissue succeeded for user {}", command.userId());
        return authTokenIssueSupport.issue(user, roles, command.clientMetadata());
    }
}
