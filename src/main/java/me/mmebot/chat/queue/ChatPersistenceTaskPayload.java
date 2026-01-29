package me.mmebot.chat.queue;

import java.time.OffsetDateTime;

public record ChatPersistenceTaskPayload(
        ChatQueueTaskType taskType,
        Long chatSessionId,
        Long userId,
        Long replyMessageId,
        Integer userMessageSeq,
        Integer assistantMessageSeq,
        String userContent,
        String assistantContent,
        int retryCount,
        String reason,
        OffsetDateTime createdAt
) {
    public ChatPersistenceTaskPayload incrementRetry(String newReason) {
        return new ChatPersistenceTaskPayload(
                taskType,
                chatSessionId,
                userId,
                replyMessageId,
                userMessageSeq,
                assistantMessageSeq,
                userContent,
                assistantContent,
                retryCount + 1,
                newReason,
                createdAt
        );
    }
}
