package me.mmebot.chat.domain;

import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import me.mmebot.openai.dto.ChatMessageRole;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ChatMessage {

    private final Long id;
    private final Long chatSessionId;
    private final Integer seq;
    private final ChatMessageRole role;
    private final String content;
    private final Long replyMsgId;
    private final OffsetDateTime createdAt;

    public boolean isUserMsg() {
        return role == ChatMessageRole.USER;
    }

    public boolean isAssistantMsg() {
        return role == ChatMessageRole.ASSISTANT;
    }
}
