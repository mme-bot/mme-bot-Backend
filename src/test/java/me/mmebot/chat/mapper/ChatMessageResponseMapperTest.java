package me.mmebot.chat.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.openai.dto.ChatMessageRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ChatMessageResponseMapper 테스트")
class ChatMessageResponseMapperTest {

    private final ChatMessageResponseMapper mapper = new ChatMessageResponseMapper();

    @Test
    @DisplayName("ChatMessage 도메인과 복호화된 메시지를 ChatMsg 응답으로 변환한다")
    void toChatMsgMapsChatMessageAndDecryptedMessage() {
        ChatMessage chatMessage = ChatMessage.builder()
                .seq(1)
                .role(ChatMessageRole.ASSISTANT)
                .build();

        ChatMsg chatMsg = mapper.toChatMsg(chatMessage, "안녕하세요");

        assertThat(chatMsg.seq()).isEqualTo(1);
        assertThat(chatMsg.role()).isEqualTo(ChatMessageRole.ASSISTANT);
        assertThat(chatMsg.msg()).isEqualTo("안녕하세요");
    }
}
