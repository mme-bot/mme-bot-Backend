package me.mmebot.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

@ConfigurationProperties(prefix = "external")
public record ExternalServiceProperties(
        List<String> allowOriginUrls,
        @DefaultValue("") String apiGateway,
        @DefaultValue("") String fileServer
) {
}
