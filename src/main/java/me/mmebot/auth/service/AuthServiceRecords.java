package me.mmebot.auth.service;

import jakarta.validation.constraints.NotBlank;
import me.mmebot.common.logging.MaskedField;

public final class AuthServiceRecords {

    private AuthServiceRecords() {
    }

    public record SignInResult(Long userId, Long botId, String nickname, String accessToken, String refreshToken) {
    }

    public record TokenPair(String accessToken, String refreshToken) {
    }

    public record SignUpCommand(
            @NotBlank
            String email,
            @NotBlank
            @MaskedField String password,
            @NotBlank
            String nickname
    ) {
    }

    public record ClientMetadata(String userAgent, String ipAddress) {
    }

    public record SendEmailVerificationResult(Long emailVerificationId, String code) {
    }
}
