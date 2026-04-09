package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.command.SignInCommand;
import me.mmebot.auth.application.port.in.SignInUseCase;
import me.mmebot.auth.application.port.out.LoadUserPort;
import me.mmebot.auth.application.port.out.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.PasswordEncodePort;
import me.mmebot.auth.application.result.SignInResult;
import me.mmebot.auth.application.result.TokenPairResult;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class SignInService implements SignInUseCase {

    private final LoadUserPort loadUserPort;
    private final PasswordEncodePort passwordEncodePort;
    private final LoadUserRolesPort loadUserRolesPort;
    private final AuthTokenIssueSupport authTokenIssueSupport;

    @Override
    public SignInResult signIn(SignInCommand command) {
        String normalizedEmail = command.email().trim().toLowerCase();

        User user = loadUserPort.loadByNormalizedEmail(normalizedEmail)
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
        log.info("Sign-in succeeded for user {}", user.getId());
        return new SignInResult(user.getId(), botId, user.getNickname(),
                tokenPair.accessToken(), tokenPair.refreshToken());
    }
}
