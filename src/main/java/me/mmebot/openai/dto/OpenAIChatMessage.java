package me.mmebot.openai.dto;

public record OpenAIChatMessage(
        String role,
        String msg
) {
}
