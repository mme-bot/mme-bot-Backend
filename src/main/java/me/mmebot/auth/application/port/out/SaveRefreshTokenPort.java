package me.mmebot.auth.application.port.out;

import me.mmebot.auth.domain.AuthToken;

public interface SaveRefreshTokenPort {
    AuthToken save(AuthToken authToken);
}
