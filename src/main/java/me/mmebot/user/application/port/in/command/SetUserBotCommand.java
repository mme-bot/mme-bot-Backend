package me.mmebot.user.application.port.in.command;

public record SetUserBotCommand(
        Long userId,
        Long botId
) {
}
