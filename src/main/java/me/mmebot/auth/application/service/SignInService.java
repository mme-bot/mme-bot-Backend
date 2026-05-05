package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.in.SignInUseCase;
import me.mmebot.auth.application.port.in.command.session.SignInCommand;
import me.mmebot.auth.application.port.in.result.session.SignInResult;
import me.mmebot.auth.application.port.in.result.session.TokenPairResult;
import me.mmebot.auth.application.port.out.crypto.PasswordPort;
import me.mmebot.auth.application.port.out.persistence.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.persistence.UserPersistencePort;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.user.domain.NormalizedEmail;
import me.mmebot.user.domain.User;

@RequiredArgsConstructor
@Transactional
@Slf4j
public class SignInService implements SignInUseCase {

    private final UserPersistencePort userPersistencePort;
    private final PasswordPort passwordPort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public SignInResult signIn(SignInCommand command) {
        NormalizedEmail normalizedEmail = NormalizedEmail.from(command.email());

        User user = userPersistencePort.loadByNormalizedEmail(normalizedEmail.value())
                .orElseThrow(() -> {
                    log.warn("Sign-in failed: no user found for {}", normalizedEmail);
                    return AuthException.invalidCredentials();
                });

        if (!passwordPort.matches(command.password(), user.getPassword())) {
            log.warn("Sign-in failed: invalid credentials for {}", normalizedEmail);
            throw AuthException.invalidCredentials();
        }

        if (!user.isActive()) {
            log.warn("Sign-in failed: user {} is marked as deleted", user.getId());
            throw AuthException.deletedAccount();
        }

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(user.getId());

        TokenPairResult tokenPair = authTokenIssueSupport.issue(user, roles, command.clientMetadata());

        Long botId = user.getBotId();
        return new SignInResult(user.getId(), botId, user.getNickname(),
                tokenPair.accessToken(), tokenPair.refreshToken());
    }
}
