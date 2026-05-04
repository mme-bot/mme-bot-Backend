package me.mmebot.chat.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import me.mmebot.openai.dto.ChatMessageRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ChatMessages 도메인 테스트")
class ChatMessagesTest {

    @Test
    @DisplayName("메시지 목록이 비어 있으면 비어 있는 대화로 판단한다")
    void isEmptyReturnsTrueWhenMessagesAreEmpty() {
        ChatMessages chatMessages = ChatMessages.from(List.of());

        assertThat(chatMessages.isEmpty()).isTrue();
        assertThat(chatMessages.hasMessages()).isFalse();
    }

    @Test
    @DisplayName("메시지 목록이 있으면 메시지가 있는 대화로 판단한다")
    void hasMessagesReturnsTrueWhenMessagesExist() {
        ChatMessages chatMessages = ChatMessages.from(List.of(
                chatMessage(1L, 1)
        ));

        assertThat(chatMessages.hasMessages()).isTrue();
        assertThat(chatMessages.isEmpty()).isFalse();
    }

    @Test
    @DisplayName("메시지를 seq 오름차순으로 정렬한다")
    void sortedBySeqReturnsMessagesInAscendingSeqOrder() {
        ChatMessage third = chatMessage(3L, 3);
        ChatMessage first = chatMessage(1L, 1);
        ChatMessage second = chatMessage(2L, 2);
        ChatMessages chatMessages = ChatMessages.from(List.of(third, first, second));

        assertThat(chatMessages.sortedBySeq())
                .extracting(ChatMessage::getSeq)
                .containsExactly(1, 2, 3);
    }

    @Test
    @DisplayName("정렬해도 원본 메시지 목록 순서는 바뀌지 않는다")
    void sortedBySeqDoesNotMutateOriginalMessages() {
        ChatMessage second = chatMessage(2L, 2);
        ChatMessage first = chatMessage(1L, 1);
        ChatMessages chatMessages = ChatMessages.from(List.of(second, first));

        chatMessages.sortedBySeq();

        assertThat(chatMessages.getMessages())
                .extracting(ChatMessage::getSeq)
                .containsExactly(2, 1);
    }

    private ChatMessage chatMessage(Long id, Integer seq) {
        return ChatMessage.builder()
                .id(id)
                .seq(seq)
                .role(ChatMessageRole.USER)
                .build();
    }
}
