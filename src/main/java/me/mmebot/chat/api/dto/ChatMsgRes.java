package me.mmebot.chat.api.dto;

import me.mmebot.openai.dto.ChatMessageRole;

public class ChatMsgRes {
    public record StartChatRes(
            Long chatMsgId,
            String msg
    ) {}
    public record CreateChatMsgRes(
            Long chatMsgId,
            Integer seq,
            ChatMessageRole role,
            String msg
    ) {}

    public record ChatMsg(
            int seq,
            ChatMessageRole role,
            String msg
    ) {}

    public record StartChatInitRes(
            String streamId
    ) {}
}
