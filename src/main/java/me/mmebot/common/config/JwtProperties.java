package me.mmebot.common.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String keyId,
        String issuer,
        String secretKey,
        Duration accessTokenExpiry,
        Duration refreshTokenExpiry
) {
}
