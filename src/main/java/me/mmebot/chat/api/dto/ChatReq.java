package me.mmebot.chat.api.dto;

import jakarta.validation.constraints.NotNull;

public final class ChatReq {
    public record CreateChatSessionReq(
            @NotNull
            Long userId,
            @NotNull
            Long diaryId
    ) {}
}
