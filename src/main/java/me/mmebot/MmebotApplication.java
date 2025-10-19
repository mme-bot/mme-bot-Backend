package me.mmebot;

import me.mmebot.common.config.ExternalServiceProperties;
import me.mmebot.common.config.JwtProperties;
import me.mmebot.common.mail.GoogleProperties;
import me.mmebot.common.persistence.ApiProp;
import me.mmebot.core.config.EncryptionKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        ApiProp.class,
        ExternalServiceProperties.class,
        JwtProperties.class,
        EncryptionKeyProperties.class,
        GoogleProperties.class
})
public class MmebotApplication {

	static void main(String[] args) {
		SpringApplication.run(MmebotApplication.class, args);
	}

}
