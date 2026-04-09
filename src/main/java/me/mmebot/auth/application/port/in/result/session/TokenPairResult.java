package me.mmebot.auth.application.port.in.result.session;

public record TokenPairResult(
        String accessToken,
        String refreshToken
) {
}
