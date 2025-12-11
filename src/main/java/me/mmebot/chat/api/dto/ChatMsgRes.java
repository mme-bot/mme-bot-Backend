package me.mmebot.chat.api.dto;

public class ChatMsgRes {
    public record StartChatRes(
            String msg
    ) {}
    public record CreateChatMsgRes(
            String msg
    ) {}
}
