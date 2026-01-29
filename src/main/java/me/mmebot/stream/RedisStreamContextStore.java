package me.mmebot.stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Primary
@RequiredArgsConstructor
public class RedisStreamContextStore implements StreamContextStore {

    private static final Duration CONTEXT_TTL = Duration.ofMinutes(5);
    private static final String STREAM_CONTEXT_KEY_PREFIX = "chat:stream:context:";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_DATA = "data";

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public void save(String streamId, StreamContext context) {
        redisTemplate.opsForValue().set(buildKey(streamId), serialize(context), CONTEXT_TTL);
    }

    @Override
    public StreamContext get(String streamId) {
        String raw = redisTemplate.opsForValue().get(buildKey(streamId));
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        return deserialize(raw);
    }

    @Override
    public void remove(String streamId) {
        redisTemplate.delete(buildKey(streamId));
    }

    private String buildKey(String streamId) {
        return STREAM_CONTEXT_KEY_PREFIX + streamId;
    }

    private String serialize(StreamContext context) {
        try {
            ObjectNode root = objectMapper.createObjectNode();
            root.put(FIELD_TYPE, context.type().name());
            root.set(FIELD_DATA, objectMapper.valueToTree(context));
            return objectMapper.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize stream context", e);
        }
    }

    private StreamContext deserialize(String raw) {
        try {
            JsonNode node = objectMapper.readTree(raw);
            JsonNode typeNode = node.get(FIELD_TYPE);
            JsonNode data = node.get(FIELD_DATA);
            if (typeNode == null || data == null) {
                return null;
            }
            StreamContextType type = StreamContextType.valueOf(typeNode.asText());
            return switch (type) {
                case FIRST_CHAT -> objectMapper.treeToValue(data, StreamContextContent.FirstChatStreamContext.class);
                case CONTINUE_CHAT -> objectMapper.treeToValue(data, StreamContextContent.ChatStreamContext.class);
            };
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize stream context", e);
        }
    }
}
