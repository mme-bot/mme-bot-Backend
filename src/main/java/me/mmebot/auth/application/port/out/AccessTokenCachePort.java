package me.mmebot.auth.application.port.out;

import java.time.Duration;

public interface AccessTokenCachePort {
    void cache(Long userId, String encryptedAccessToken, Duration ttl);
}
