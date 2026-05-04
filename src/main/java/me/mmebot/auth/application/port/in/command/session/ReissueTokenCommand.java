package me.mmebot.auth.application.port.in.command.session;

public record ReissueTokenCommand(
        Long userId,
        String refreshToken,
        ClientMetadata clientMetadata
) {
}
