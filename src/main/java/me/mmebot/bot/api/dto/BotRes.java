package me.mmebot.bot.api.dto;

public class BotRes {
    public record BotNameRes(Long botId, String botName) {}
    public record BotIdRes(Long botId) {}
}
