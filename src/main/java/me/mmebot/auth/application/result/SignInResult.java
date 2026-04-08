package me.mmebot.auth.application.result;

public record SignInResult(
        Long userId,
        Long botId,
        String nickname,
        String accessToken,
        String refreshToken
) {
}
