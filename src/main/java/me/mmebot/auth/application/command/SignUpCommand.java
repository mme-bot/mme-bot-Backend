package me.mmebot.auth.application.command;

public record SignUpCommand(
        String email,
        String password,
        String nickname
) {
}
