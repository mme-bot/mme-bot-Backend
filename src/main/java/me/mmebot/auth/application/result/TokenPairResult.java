package me.mmebot.auth.application.result;

public record TokenPairResult(
        String accessToken,
        String refreshToken
) {
}
