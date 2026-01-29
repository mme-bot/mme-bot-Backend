package me.mmebot.chat.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "chat.persistence")
public record ChatPersistenceQueueProperties(
        @DefaultValue("chat:pending:first-message") String queueKey,
        @DefaultValue("chat:dead:first-message") String deadLetterKey,
        @DefaultValue("5") int maxRetry,
        @DefaultValue("5") int batchSize,
        @DefaultValue("5000") long workerDelay
) {
}
