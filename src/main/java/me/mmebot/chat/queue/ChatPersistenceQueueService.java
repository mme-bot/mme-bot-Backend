package me.mmebot.chat.queue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.chat.config.ChatPersistenceQueueProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class ChatPersistenceQueueService {

    private static final int MAX_REASON_LENGTH = 512;

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final ChatPersistenceQueueProperties properties;

    public void enqueueFirstMessageFallback(Long chatSessionId,
                                            Long userId,
                                            int assistantSeq,
                                            String assistantContent,
                                            Throwable reason) {
        ChatPersistenceTaskPayload payload = new ChatPersistenceTaskPayload(
                ChatQueueTaskType.FIRST_MESSAGE,
                chatSessionId,
                userId,
                null,
                null,
                assistantSeq,
                null,
                assistantContent,
                0,
                sanitizeReason(reason),
                OffsetDateTime.now()
        );
        enqueue(payload);
        log.warn("Enqueued first message fallback for chatSessionId={}, userId={}", chatSessionId, userId);
    }

    public void enqueueChatMessagePairFallback(Long chatSessionId,
                                               Long userId,
                                               Long replyMessageId,
                                               int userSeq,
                                               int assistantSeq,
                                               String userContent,
                                               String assistantContent,
                                               Throwable reason) {
        ChatPersistenceTaskPayload payload = new ChatPersistenceTaskPayload(
                ChatQueueTaskType.CHAT_MESSAGE_PAIR,
                chatSessionId,
                userId,
                replyMessageId,
                userSeq,
                assistantSeq,
                userContent,
                assistantContent,
                0,
                sanitizeReason(reason),
                OffsetDateTime.now()
        );
        enqueue(payload);
        log.warn("Enqueued chat message pair fallback for chatSessionId={}, userId={}, replyMessageId={}",
                chatSessionId,
                userId,
                replyMessageId);
    }

    public void enqueue(ChatPersistenceTaskPayload payload) {
        redisTemplate.opsForList().rightPush(properties.queueKey(), serialize(payload));
    }

    public ChatPersistenceTaskPayload pop() {
        String raw = redisTemplate.opsForList().leftPop(properties.queueKey());
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        return deserialize(raw);
    }

    public void moveToDeadLetter(ChatPersistenceTaskPayload payload) {
        redisTemplate.opsForList().rightPush(properties.deadLetterKey(), serialize(payload));
        log.error("Moved chat persistence payload to dead letter queue: chatSessionId={}, userId={}, task={}",
                payload.chatSessionId(),
                payload.userId(),
                payload.taskType());
    }

    private String sanitizeReason(Throwable reason) {
        if (reason == null || !StringUtils.hasText(reason.getMessage())) {
            return "unknown";
        }
        String message = reason.getMessage();
        if (message.length() <= MAX_REASON_LENGTH) {
            return message;
        }
        return message.substring(0, MAX_REASON_LENGTH);
    }

    private String serialize(ChatPersistenceTaskPayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize chat persistence payload", e);
        }
    }

    private ChatPersistenceTaskPayload deserialize(String raw) {
        try {
            return objectMapper.readValue(raw, ChatPersistenceTaskPayload.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize chat persistence payload", e);
        }
    }
}
