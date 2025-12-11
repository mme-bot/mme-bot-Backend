package me.mmebot.chat.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ChatMsgReq {
    public record CreateChatMsgReq(
            @NotNull
            Long userId,
            @NotNull
            Integer prevSeq,
            @NotBlank
            String msg
    ) {}
}
