package me.mmebot.openai.dto;

public enum ChatMessageRole {
    USER,
    ASSISTANT;

    public String toValue() {
        return name().toLowerCase();
    }
}
