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
import me.mmebot.auth.application.port.out.crypto.PasswordPort;
import me.mmebot.auth.application.port.out.persistence.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.persistence.RefreshTokenPort;
import me.mmebot.auth.application.port.out.persistence.UserPersistencePort;
import me.mmebot.auth.domain.AuthToken;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.user.domain.NormalizedEmail;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AuthSessionService implements SignInUseCase, ReissueTokenUseCase, LogoutUseCase {

    private final UserPersistencePort userPersistencePort;
    private final PasswordPort passwordPort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final RefreshTokenPort refreshTokenPort;
    private final RefreshTokenValidator refreshTokenValidator;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public SignInResult signIn(SignInCommand command) {
        NormalizedEmail normalizedEmail = NormalizedEmail.from(command.email());

        User user = userPersistencePort.loadByNormalizedEmail(normalizedEmail.value())
                .orElseThrow(() -> {
                    log.warn("Sign-in failed: no user found for {}", normalizedEmail);
                    return AuthException.invalidCredentials();
                });

        ensureActiveUser(user, "Sign-in failed");

        if (!passwordPort.matches(command.password(), user.getPassword())) {
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

        refreshTokenValidator.validate(command, authToken);

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
        if (!user.isActive()) {
            log.warn("{}: user {} is marked as deleted", logPrefix, user.getId());
            throw AuthException.deletedAccount();
        }
    }
}
