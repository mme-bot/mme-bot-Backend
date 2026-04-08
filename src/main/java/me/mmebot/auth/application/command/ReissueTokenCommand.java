package me.mmebot.auth.application.command;

public record ReissueTokenCommand(
        Long userId,
        String refreshToken,
        ClientMetadata clientMetadata
) {
}
