package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SignInResponse(
        @NotNull
        Long userId,

        Long botId,

        @NotBlank
        String nickname,

        @NotBlank
        String accessToken,

        @NotBlank
        String refreshToken
) {
}
