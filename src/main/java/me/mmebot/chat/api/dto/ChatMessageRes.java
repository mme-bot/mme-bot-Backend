package me.mmebot.chat.api.dto;

public class ChatMessageRes {
    public record CreateChatMessageRes(
            String message
    ) {}
}
