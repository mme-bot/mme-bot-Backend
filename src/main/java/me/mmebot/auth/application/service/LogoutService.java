
package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.port.in.LogoutUseCase;
import me.mmebot.auth.application.port.in.command.session.LogoutCommand;
import me.mmebot.auth.application.port.out.persistence.RefreshTokenPort;
import me.mmebot.auth.exception.AuthException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class LogoutService implements LogoutUseCase {

    private final RefreshTokenPort refreshTokenPort;

    @Override
    public void logout(LogoutCommand command) {
        if (command.userId() == null) {
            throw AuthException.authenticationRequired();
        }
        if (command.refreshToken() == null || command.refreshToken().isBlank()) {
            throw AuthException.refreshTokenMissing();
        }

        refreshTokenPort.loadByUserIdAndToken(command.userId(), command.refreshToken())
                .filter(token -> !token.isRevoked())
                .ifPresent(token -> {
                    token.revoke(OffsetDateTime.now());
                    refreshTokenPort.save(token);
                    log.debug("Refresh token revoked for user {}", command.userId());
                });
    }
}