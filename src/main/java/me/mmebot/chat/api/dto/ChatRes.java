package me.mmebot.chat.api.dto;

public final class ChatRes {

    public record CreateChatSessionRes(
            Long chatSessionId
    ) {}
}
