package me.mmebot.auth.application.port.in.command.registration;

public record SignUpCommand(
        String email,
        String password,
        String nickname
) {
}
