package me.mmebot.auth.application.port.out.persistence;

import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;

public interface RefreshTokenPort {
    Optional<AuthToken> loadByUserIdAndToken(Long userId, String token);
    AuthToken save(AuthToken authToken);
}
