package me.mmebot.auth.service;

public final class AuthServiceRecords {

    private AuthServiceRecords() {
    }

    public record SignInResult(Long userId, Long botId, String nickname, String accessToken, String refreshToken) {
    }

    public record TokenPair(String accessToken, String refreshToken) {
    }

    public record SignUpCommand(String email, String password, String nickname, Long emailVerificationId) {
    }

    public record ClientMetadata(String userAgent, String ipAddress) {
    }

    public record SendEmailVerificationResult(Long emailVerificationId, String code) {
    }
}
