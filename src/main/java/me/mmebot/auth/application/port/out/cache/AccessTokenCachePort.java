package me.mmebot.auth.application.port.out.cache;

import java.time.Duration;

public interface AccessTokenCachePort {
    void cache(Long userId, String encryptedAccessToken, Duration ttl);
}
