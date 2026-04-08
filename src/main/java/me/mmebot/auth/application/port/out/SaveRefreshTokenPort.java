package me.mmebot.auth.application.port.out;

import me.mmebot.auth.domain.AuthTokenEntity;

public interface SaveRefreshTokenPort {
    AuthTokenEntity save(AuthTokenEntity authToken);
}
