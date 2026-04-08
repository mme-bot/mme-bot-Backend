package me.mmebot.auth.adapter.out.redis;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.AccessTokenCachePort;
import me.mmebot.auth.service.RedisService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AccessTokenRedisAdapter implements AccessTokenCachePort {

    private static final String KEY_PREFIX = "jwt:";

    private final RedisService redisService;

    @Override
    public void cache(Long userId, String encryptedAccessToken, Duration ttl) {
        redisService.enqueueRedis(KEY_PREFIX + userId, encryptedAccessToken, ttl);
    }
}
