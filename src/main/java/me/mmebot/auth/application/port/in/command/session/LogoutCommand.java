package me.mmebot.auth.application.port.in.command.session;

public record LogoutCommand(
        Long userId,
        String refreshToken
) {
}
