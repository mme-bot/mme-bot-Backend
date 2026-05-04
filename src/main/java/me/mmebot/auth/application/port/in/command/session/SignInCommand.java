package me.mmebot.auth.application.port.in.command.session;

public record SignInCommand(
        String email,
        String password,
        ClientMetadata clientMetadata
) {
}
