package me.mmebot.stream;

import java.time.LocalDateTime;

public interface StreamContext {
    StreamContextType type();
    LocalDateTime createdAt();
}
