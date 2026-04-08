package me.mmebot.auth.application.port.out;

import java.util.Optional;
import me.mmebot.auth.domain.AuthTokenEntity;

public interface LoadRefreshTokenPort {
    Optional<AuthTokenEntity> loadByUserIdAndToken(Long userId, String token);
}
