package me.mmebot.auth.application.command;

public record SignInCommand(
        String email,
        String password,
        ClientMetadata clientMetadata
) {
}
