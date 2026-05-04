package me.mmebot.user.application.port.in.command;

public record CreateTestUserCommand(
        Long botId,
        String nickname
) {
}
