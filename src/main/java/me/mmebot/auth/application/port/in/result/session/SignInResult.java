package me.mmebot.auth.application.port.in.result.session;

public record SignInResult(
        Long userId,
        Long botId,
        String nickname,
        String accessToken,
        String refreshToken
) {
}
