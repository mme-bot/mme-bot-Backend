package me.mmebot.config;

import java.time.Duration;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StringUtils;

@Configuration
@EnableConfigurationProperties(RedisProperties.class)
public class RedisConfig {

    @Bean
    public RedisConnectionFactory redisConnectionFactory(RedisProperties properties) {
        RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration();
        String host = properties.getHost();
        configuration.setHostName(StringUtils.hasText(host) ? host : "localhost");
        configuration.setPort(properties.getPort());
        configuration.setDatabase(properties.getDatabase());
        if (StringUtils.hasText(properties.getUsername())) {
            configuration.setUsername(properties.getUsername());
        }
        if (StringUtils.hasText(properties.getPassword())) {
            configuration.setPassword(RedisPassword.of(properties.getPassword()));
        }

        LettuceClientConfiguration.LettuceClientConfigurationBuilder builder = LettuceClientConfiguration.builder();
        Duration timeout = properties.getTimeout();
        if (timeout != null && !timeout.isNegative() && !timeout.isZero()) {
            builder.commandTimeout(timeout);
        }
        RedisProperties.Ssl ssl = properties.getSsl();
        if (ssl != null && ssl.isEnabled()) {
            builder.useSsl();
        }
        return new LettuceConnectionFactory(configuration, builder.build());
    }

    @Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        return new StringRedisTemplate(redisConnectionFactory);
    }
}
