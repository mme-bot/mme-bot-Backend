package me.mmebot.openai.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import me.mmebot.chat.domain.ChatMessageEntity;
import me.mmebot.openai.dto.ChatMessageRole;
import org.springframework.stereotype.Component;

/**
 * OpenAI Chat 요청 메시지 구성 유틸리티.
 * 시스템 프롬프트, 히스토리, 사용자 입력을 OpenAI 형식으로 변환한다.
 */
@Component
public class OpenAIChatRequestBuilder {

    /**
     * 시스템 프롬프트 + 대화 히스토리 + 사용자 입력을 OpenAI 메시지 리스트로 변환한다.
     */
    public List<Map<String, String>> buildMessages(
            String systemPrompt,
            List<ChatMessageEntity> history,
            String userPrompt
    ) {
        List<Map<String, String>> messages = new ArrayList<>();

        if (systemPrompt != null && !systemPrompt.isBlank()) {
            messages.add(Map.of(
                    "role", "system",
                    "content", systemPrompt
            ));
        }

        if (history != null && !history.isEmpty()) {
            for (ChatMessageEntity msg : history) {
                messages.add(Map.of(
                        "role", toOpenAiRole(msg.getRole()),
                        "content", msg.getContent()
                ));
            }
        }

        if (userPrompt != null) {
            messages.add(Map.of(
                    "role", "user",
                    "content", userPrompt
            ));
        }

        return messages;
    }

    /**
     * 내부 도메인 역할을 OpenAI 역할 문자열로 변환한다.
     */
    private String toOpenAiRole(ChatMessageRole role) {
        return switch (role) {
            case USER -> "user";
            case ASSISTANT -> "assistant";
        };
    }
}
