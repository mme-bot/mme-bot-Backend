package me.mmebot.common.config;

import com.openai.client.OpenAIClient;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.web.reactive.function.client.WebClient;

@TestConfiguration
public class TestOpenAIConfig {

    @Bean
    @Primary
    public OpenAIClient openAIClient() {
        return Mockito.mock(OpenAIClient.class);
    }

    @Bean
    @Primary
    public WebClient openAiWebClient() {
        return WebClient.builder()
                .baseUrl("http://localhost")
                .build();
    }
}
