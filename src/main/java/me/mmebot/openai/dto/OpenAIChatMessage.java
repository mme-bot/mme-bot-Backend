package me.mmebot.openai.dto;

public record OpenAIChatMessage(
        ChatMessageRole role,
        String message
) {
}
