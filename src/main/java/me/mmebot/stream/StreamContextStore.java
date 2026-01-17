package me.mmebot.stream;

public interface StreamContextStore {
    void save(String streamId, StreamContext context);
    StreamContext get(String streamId);
    void remove(String streamId);
}
