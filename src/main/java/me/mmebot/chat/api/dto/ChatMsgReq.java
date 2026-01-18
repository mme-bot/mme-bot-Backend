package me.mmebot.chat.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ChatMsgReq {
    public record StartChatReq(
            @NotNull
            Long userId
    ) {}
    public record CreateChatMsgReq(
            @NotNull
            Long userId,
            @NotNull
            Long replyToMsgId,
            @NotBlank
            String msg
    ) {}
}
