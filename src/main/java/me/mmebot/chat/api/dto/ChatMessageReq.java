package me.mmebot.chat.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ChatMessageReq {
    public record CreateChatMessageReq(
            @NotNull
            Long userId,
            @NotNull
            Integer prevSeq,
            @NotBlank
            String message
    ) {}
}
