package me.mmebot.common.config;

import me.mmebot.common.crypto.AesGcmCryptoService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class CryptoTestConfig {

    @Bean
    public AesGcmCryptoService aesGcmCryptoService() {
        return new AesGcmCryptoService(
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        );
    }
}
