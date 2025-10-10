package me.mmebot.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "key")
public record EncryptionKeyProperties(
        String algorithm,
        Length length
) {

    public record Length(
            int tag,
            int iv,
            int key
    ) {
    }
}
