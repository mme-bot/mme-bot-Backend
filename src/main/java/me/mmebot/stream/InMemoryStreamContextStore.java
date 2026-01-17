package me.mmebot.stream;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryStreamContextStore implements StreamContextStore {

    private final Map<String, StreamContext> store = new ConcurrentHashMap<>();

    @Override
    public void save(String streamId, StreamContext context) {
        store.put(streamId, context);
    }

    @Override
    public StreamContext get(String streamId) {
        return store.getOrDefault(streamId, null);
    }

    @Override
    public void remove(String streamId) {
        store.remove(streamId);
    }
}
