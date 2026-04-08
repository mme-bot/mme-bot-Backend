package me.mmebot.openai.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * OpenAI 관련 설정 바인딩.
 */
@Validated
@ConfigurationProperties(prefix = "openai")
public class OpenAIProperties {

    /**
     * Chat 관련 설정.
     */
    private final Chat chat = new Chat();

    public Chat getChat() {
        return chat;
    }

    @Validated
    public static class Chat {
        /**
         * 사용할 Chat 모델명 (예: gpt-4.1-mini)
         */
        @NotBlank(message = "openai.chat.model 값은 공백일 수 없습니다.")
        private String model = "gpt-4.1-mini";

        public String getModel() {
            return model;
        }

        public void setModel(String model) {
            this.model = model;
        }
    }
}
