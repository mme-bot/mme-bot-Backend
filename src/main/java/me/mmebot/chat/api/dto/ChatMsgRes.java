package me.mmebot.chat.api.dto;

import me.mmebot.openai.dto.ChatMessageRole;

public class ChatMsgRes {
    public record StartChatRes(
            String msg
    ) {}
    public record CreateChatMsgRes(
            String msg
    ) {}

    public record ChatMsg(
            int seq,
            ChatMessageRole role,
            String msg
    ) {}
}
