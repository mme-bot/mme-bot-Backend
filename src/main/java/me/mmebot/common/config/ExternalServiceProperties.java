package me.mmebot.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "external")
public record ExternalServiceProperties(
        String frontendUrl,
        @DefaultValue("") String apiGateway,
        @DefaultValue("") String fileServer
) {
}
