package me.mmebot.openai.dto;

public record ChatStreamResponse(
        long seq,
        String content
) {}
