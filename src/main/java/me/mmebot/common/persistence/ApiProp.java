package me.mmebot.common.persistence;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "api")
public record ApiProp(String basePath) {
}
