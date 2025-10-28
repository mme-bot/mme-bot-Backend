package me.mmebot.common.mail;

import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.service.ProviderTokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class MailConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "google", name = "enabled", havingValue = "true")
    public MailSender gmailMailSender(GoogleProperties properties, ProviderTokenService providerTokenService) {
        log.info("google.enabled=true. Configuring GmailMailSender for {}", properties.userEmail());
        return new GmailMailSender(properties, providerTokenService);
    }

    @Bean
    @ConditionalOnMissingBean(MailSender.class)
    public MailSender noopMailSender() {
        log.info("gmail.enabled!=true. Using NoopMailSender for outbound email");
        return new NoopMailSender();
    }
}
