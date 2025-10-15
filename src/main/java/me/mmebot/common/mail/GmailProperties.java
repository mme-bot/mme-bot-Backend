package me.mmebot.common.mail;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gmail")
public record GmailProperties(
        boolean enabled,
        String applicationName,
        String userEmail,
        String fromDisplayName,
        String clientId,
        String clientSecret,
        String refreshToken
) {
}
