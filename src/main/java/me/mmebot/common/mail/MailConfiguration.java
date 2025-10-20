package me.mmebot.common.mail;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class MailConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "gmail", name = "enabled", havingValue = "true")
    public MailSender gmailMailSender(GoogleProperties properties) {
        log.info("gmail.enabled=true. Configuring GmailMailSender for {}", properties.userEmail());
        return new GmailMailSender(properties);
    }

    @Bean
    @ConditionalOnMissingBean(MailSender.class)
    public MailSender noopMailSender() {
        log.info("gmail.enabled!=true. Using NoopMailSender for outbound email");
        return new NoopMailSender();
    }
}
