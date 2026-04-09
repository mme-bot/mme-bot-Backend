package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.in.SignInUseCase;
import me.mmebot.auth.application.port.in.command.session.SignInCommand;
import me.mmebot.auth.application.port.in.result.session.SignInResult;
import me.mmebot.auth.application.port.in.result.session.TokenPairResult;
import me.mmebot.auth.application.port.out.crypto.PasswordEncodePort;
import me.mmebot.auth.application.port.out.persistence.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.persistence.UserPersistencePort;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class SignInService implements SignInUseCase {

    private final UserPersistencePort userPersistencePort;
    private final PasswordEncodePort passwordEncodePort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public SignInResult signIn(SignInCommand command) {
        String normalizedEmail = command.email().trim().toLowerCase();

        User user = userPersistencePort.loadByNormalizedEmail(normalizedEmail)
                .orElseThrow(() -> {
                    log.warn("Sign-in failed: no user found for {}", normalizedEmail);
                    return AuthException.invalidCredentials();
                });

        if (user.isDeleted()) {
            log.warn("Sign-in failed: user {} is marked as deleted", user.getId());
            throw AuthException.deletedAccount();
        }

        if (!passwordEncodePort.matches(command.password(), user.getPassword())) {
            log.warn("Sign-in failed: invalid credentials for {}", normalizedEmail);
            throw AuthException.invalidCredentials();
        }

        List<RoleName> roles = loadUserRolesPort.loadRoleNames(user.getId());

        TokenPairResult tokenPair = authTokenIssueSupport.issue(user, roles, command.clientMetadata());

        Long botId = user.getBotId();
        return new SignInResult(user.getId(), botId, user.getNickname(),
                tokenPair.accessToken(), tokenPair.refreshToken());
    }
}
