package me.mmebot.auth.application.service;

import java.time.OffsetDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.in.command.session.ReissueTokenCommand;
import me.mmebot.auth.application.port.out.crypto.TokenCipherPort;
import me.mmebot.auth.application.port.out.crypto.TokenHashPort;
import me.mmebot.auth.application.port.out.jwt.JwtParsePort;
import me.mmebot.auth.application.port.out.persistence.RefreshTokenPort;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenPayloadTypeMismatchException;
import me.mmebot.auth.domain.AuthTokenUserMismatchException;
import me.mmebot.auth.domain.InvalidAuthTokenTypeException;
import me.mmebot.auth.domain.UnusableAuthTokenException;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenValidator {

    private final TokenHashPort tokenHashPort;
    private final TokenCipherPort tokenCipherPort;
    private final JwtParsePort jwtParsePort;
    private final RefreshTokenPort refreshTokenPort;

    public void validate(ReissueTokenCommand command, AuthToken authToken) {
        ensureRefreshToken(authToken);

        OffsetDateTime now = OffsetDateTime.now();
        ensureUsable(command, authToken, now);
        ensureAadHashMatches(command, authToken, now);
        ensurePayloadMatches(command, authToken, now);
    }

    private void ensureRefreshToken(AuthToken authToken) {
        try {
            authToken.ensureRefreshToken();
        } catch (InvalidAuthTokenTypeException ex) {
            log.warn("Token reissue failed: token {} is not a refresh token", authToken.getId());
            throw AuthException.refreshTokenMissing();
        }
    }

    private void ensureUsable(ReissueTokenCommand command, AuthToken authToken, OffsetDateTime now) {
        try {
            authToken.ensureUsable(now);
        } catch (UnusableAuthTokenException ex) {
            log.warn("Token reissue failed: refresh token invalid for user {}", command.userId());
            throw AuthException.refreshTokenInvalid();
        }
    }

    private void ensureAadHashMatches(ReissueTokenCommand command, AuthToken authToken, OffsetDateTime now) {
        byte[] userHash = tokenHashPort.hash(command.userId().toString());
        if (!authToken.matchesAadHash(userHash)) {
            log.warn("Token reissue failed: aad hash mismatch for user {}", command.userId());
            revokeRefreshToken(authToken, now);
            throw AuthException.refreshTokenInvalid();
        }
    }

    private void ensurePayloadMatches(ReissueTokenCommand command, AuthToken authToken, OffsetDateTime now) {
        String decryptedToken = tokenCipherPort.decrypt(
                authToken.getToken(),
                authToken.getEncryptionContext(),
                authToken.getType(),
                command.userId().toString()
        );

        JwtPayload payload = jwtParsePort.parse(decryptedToken);

        try {
            authToken.ensureMatchesPayload(payload, command.userId());
        } catch (AuthTokenUserMismatchException ex) {
            log.warn("Token reissue failed: payload user mismatch (expected {}, got {})",
                    command.userId(), payload.userId());
            revokeRefreshToken(authToken, now);
            throw AuthException.refreshTokenUserMismatch();
        } catch (AuthTokenPayloadTypeMismatchException ex) {
            log.warn("Token reissue failed: invalid token type {} for user {}",
                    payload.tokenType(), command.userId());
            throw AuthException.invalidTokenType();
        }
    }

    private void revokeRefreshToken(AuthToken authToken, OffsetDateTime revokedAt) {
        authToken.revoke(revokedAt);
        refreshTokenPort.save(authToken);
    }
}
