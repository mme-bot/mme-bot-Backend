package me.mmebot.auth.application.command;

public record LogoutCommand(
        Long userId,
        String refreshToken
) {
}
