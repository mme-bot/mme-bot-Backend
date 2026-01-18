package me.mmebot.stream;

import java.time.LocalDateTime;

public class StreamContextContent {
    public record FirstChatStreamContext(
            Long chatSessionId,
            Long userId,
            LocalDateTime timestamp
    ) implements StreamContext {
        @Override
        public StreamContextType type() {
            return StreamContextType.FIRST_CHAT;
        }

        @Override
        public LocalDateTime createdAt() {
            return timestamp;
        }
    }

    public record ChatStreamContext(
            Long chatSessionId,
            Long userId,
            Long replyToMsgId,
            String msg,
            LocalDateTime timestamp
    ) implements StreamContext {

        @Override
        public StreamContextType type() {
            return StreamContextType.CONTINUE_CHAT;
        }

        @Override
        public LocalDateTime createdAt() {
            return timestamp;
        }
    }
}
