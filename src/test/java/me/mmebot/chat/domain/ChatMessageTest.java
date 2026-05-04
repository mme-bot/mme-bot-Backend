package me.mmebot.chat.domain;

import static org.assertj.core.api.Assertions.assertThat;

import me.mmebot.openai.dto.ChatMessageRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ChatMessage 도메인 테스트")
class ChatMessageTest {

    @Test
    @DisplayName("메시지 역할이 USER이면 사용자 메시지로 판단한다")
    void isUserMsgReturnsTrueWhenRoleIsUser() {
        ChatMessage chatMessage = ChatMessage.builder()
                .role(ChatMessageRole.USER)
                .build();

        assertThat(chatMessage.isUserMsg()).isTrue();
        assertThat(chatMessage.isAssistantMsg()).isFalse();
    }

    @Test
    @DisplayName("메시지 역할이 ASSISTANT이면 어시스턴트 메시지로 판단한다")
    void isAssistantMsgReturnsTrueWhenRoleIsAssistant() {
        ChatMessage chatMessage = ChatMessage.builder()
                .role(ChatMessageRole.ASSISTANT)
                .build();

        assertThat(chatMessage.isAssistantMsg()).isTrue();
        assertThat(chatMessage.isUserMsg()).isFalse();
    }
}
