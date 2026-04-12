package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.in.LogoutUseCase;
import me.mmebot.auth.application.port.in.ReissueTokenUseCase;
import me.mmebot.auth.application.port.in.SignInUseCase;
import me.mmebot.auth.application.port.in.command.session.LogoutCommand;
import me.mmebot.auth.application.port.in.command.session.ReissueTokenCommand;
import me.mmebot.auth.application.port.in.command.session.SignInCommand;
import me.mmebot.auth.application.port.in.result.session.SignInResult;
import me.mmebot.auth.application.port.in.result.session.TokenPairResult;
import me.mmebot.auth.application.port.out.crypto.PasswordEncodePort;
import me.mmebot.auth.application.port.out.crypto.TokenCipherPort;
import me.mmebot.auth.application.port.out.crypto.TokenHashPort;
import me.mmebot.auth.application.port.out.jwt.JwtParsePort;
import me.mmebot.auth.application.port.out.persistence.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.persistence.RefreshTokenPort;
import me.mmebot.auth.application.port.out.persistence.UserPersistencePort;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.AuthTokenPayloadTypeMismatchException;
import me.mmebot.auth.domain.AuthTokenType;
import me.mmebot.auth.domain.AuthTokenUserMismatchException;
import me.mmebot.auth.domain.InvalidAuthTokenTypeException;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.domain.UnusableAuthTokenException;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.user.domain.User;
import me.mmebot.user.domain.UserDeletedException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AuthSessionService implements SignInUseCase, ReissueTokenUseCase, LogoutUseCase {

    private final UserPersistencePort userPersistencePort;
    private final PasswordEncodePort passwordEncodePort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final RefreshTokenPort refreshTokenPort;
    private final TokenHashPort tokenHashPort;
    private final TokenCipherPort tokenCipherPort;
    private final JwtParsePort jwtParsePort;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public SignInResult signIn(SignInCommand command) {
        String normalizedEmail = command.email().trim().toLowerCase();

        User user = userPersistencePort.loadByNormalizedEmail(normalizedEmail)
                .orElseThrow(() -> {
                    log.warn("Sign-in failed: no user found for {}", normalizedEmail);
                    return AuthException.invalidCredentials();
                });

        ensureActiveUser(user, "Sign-in failed");

        if (!passwordEncodePort.matches(command.password(), user.getPassword())) {
            log.warn("Sign-in failed: invalid credentials for {}", normalizedEmail);
            throw AuthException.invalidCredentials();
        }

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(user.getId());
        TokenPairResult tokenPair = authTokenIssueSupport.issue(user, roles, command.clientMetadata());

        return new SignInResult(
                user.getId(),
                user.getBotId(),
                user.getNickname(),
                tokenPair.accessToken(),
                tokenPair.refreshToken()
        );
    }

    @Override
    public TokenPairResult reissue(ReissueTokenCommand command) {
        User user = userPersistencePort.loadById(command.userId())
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: user {} not found", command.userId());
                    return AuthException.userNotFound();
                });

        ensureActiveUser(user, "Token reissue failed");

        AuthToken authToken = refreshTokenPort
                .loadByUserIdAndToken(command.userId(), command.refreshToken())
                .orElseThrow(() -> {
                    log.warn("Token reissue failed: token not found for user {}", command.userId());
                    return AuthException.tokenNotFound();
                });

        validateRefreshToken(command, authToken);

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(command.userId());
        return authTokenIssueSupport.issue(user, roles, command.clientMetadata());
    }

    @Override
    public void logout(LogoutCommand command) {
        if (command.userId() == null) {
            throw AuthException.authenticationRequired();
        }

        refreshTokenPort.loadByUserIdAndToken(command.userId(), command.refreshToken())
                .filter(token -> !token.isRevoked())
                .ifPresent(token -> {
                    token.revoke(OffsetDateTime.now());
                    refreshTokenPort.save(token);
                    log.debug("Refresh token revoked for user {}", command.userId());
                });
    }

    private void ensureActiveUser(User user, String logPrefix) {
        try {
            user.ensureActive();
        } catch (UserDeletedException ex) {
            log.warn("{}: user {} is marked as deleted", logPrefix, user.getId());
            throw AuthException.deletedAccount();
        }
    }

    private void validateRefreshToken(ReissueTokenCommand command, AuthToken authToken) {
        try {
            authToken.ensureRefreshToken();
        } catch (InvalidAuthTokenTypeException ex) {
            log.warn("Token reissue failed: token {} is not a refresh token", authToken.getId());
            throw AuthException.refreshTokenMissing();
        }

        OffsetDateTime now = OffsetDateTime.now();
        try {
            authToken.ensureUsable(now);
        } catch (UnusableAuthTokenException ex) {
            log.warn("Token reissue failed: refresh token invalid for user {}", command.userId());
            throw AuthException.refreshTokenInvalid();
        }

        byte[] userHash = tokenHashPort.hash(command.userId().toString());
        if (!authToken.matchesAadHash(userHash)) {
            log.warn("Token reissue failed: aad hash mismatch for user {}", command.userId());
            revokeRefreshToken(authToken, now);
            throw AuthException.refreshTokenInvalid();
        }

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
