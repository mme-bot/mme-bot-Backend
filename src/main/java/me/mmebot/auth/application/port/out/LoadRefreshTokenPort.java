package me.mmebot.auth.application.port.out;

import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;

public interface LoadRefreshTokenPort {
    Optional<AuthToken> loadByUserIdAndToken(Long userId, String token);
}
