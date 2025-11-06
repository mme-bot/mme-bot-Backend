package me.mmebot.auth.service;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

    private final StringRedisTemplate stringRedisTemplate;

    public void enqueueRedis(String key, String value, Duration ttl) {
        stringRedisTemplate.opsForList().rightPush(key, value);
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            boolean expirationApplied = Boolean.TRUE.equals(stringRedisTemplate.expire(key, ttl));
            if (!expirationApplied) {
                log.warn("Failed to set expiration for Redis key {}", key);
            }
        } else {
            log.warn("Skipping expiration for Redis key {} due to invalid ttl {}", key, ttl);
        }
        log.debug("Stored access token in Redis queue {}", key);
    }

}
