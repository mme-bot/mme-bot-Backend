package me.mmebot.chat.queue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
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
    private static final Duration PAYLOAD_TTL = Duration.ofMinutes(5);
    private static final Duration DEAD_LETTER_TTL = Duration.ofHours(1);
    private static final String PAYLOAD_KEY_SUFFIX = ":payload:";
    private static final String SEQ_KEY_SUFFIX = ":seq";
    private static final int CLEANUP_BATCH_SIZE = 10;

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
        String serialized = serialize(payload);
        String taskId = UUID.randomUUID().toString();
        String payloadKey = buildPayloadKey(taskId);

        redisTemplate.opsForValue().set(payloadKey, serialized, PAYLOAD_TTL);
        Long sequence = redisTemplate.opsForValue().increment(sequenceKey());
        double score = sequence != null ? sequence.doubleValue() : (double) System.currentTimeMillis();
        redisTemplate.opsForZSet().add(properties.queueKey(), payloadKey, score);
    }

    public ChatPersistenceTaskPayload pop() {
        cleanupQueueReferences();
        while (true) {
            Set<String> candidates = redisTemplate.opsForZSet().range(properties.queueKey(), 0, 0);
            if (candidates == null || candidates.isEmpty()) {
                return null;
            }
            String payloadKey = candidates.iterator().next();
            Long removed = redisTemplate.opsForZSet().remove(properties.queueKey(), payloadKey);
            if (removed == null || removed == 0) {
                continue;
            }
            String raw = redisTemplate.opsForValue().get(payloadKey);
            redisTemplate.delete(payloadKey);
            if (!StringUtils.hasText(raw)) {
                continue;
            }
            return deserialize(raw);
        }
    }

    public void moveToDeadLetter(ChatPersistenceTaskPayload payload) {
        redisTemplate.opsForList().rightPush(properties.deadLetterKey(), serialize(payload));
        redisTemplate.expire(properties.deadLetterKey(), DEAD_LETTER_TTL);
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

    private String buildPayloadKey(String taskId) {
        return properties.queueKey() + PAYLOAD_KEY_SUFFIX + taskId;
    }

    private String sequenceKey() {
        return properties.queueKey() + SEQ_KEY_SUFFIX;
    }

    private void cleanupQueueReferences() {
        Set<String> range = redisTemplate.opsForZSet().range(properties.queueKey(), 0, CLEANUP_BATCH_SIZE - 1);
        if (range == null || range.isEmpty()) {
            return;
        }
        List<String> stale = new ArrayList<>();
        for (String payloadKey : range) {
            Boolean exists = redisTemplate.hasKey(payloadKey);
            if (exists == null || !exists) {
                stale.add(payloadKey);
            }
        }
        if (!stale.isEmpty()) {
            redisTemplate.opsForZSet().remove(properties.queueKey(), stale.toArray());
        }
    }
}
