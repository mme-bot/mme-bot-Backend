package me.mmebot.common.mail;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "google")
public record GoogleProperties(
        String tokenUrl,
        boolean enabled,
        String applicationName,
        String userEmail,
        String fromDisplayName,
        String clientId,
        String clientSecret,
        String refreshToken,
        String redirectUri
) {
}
