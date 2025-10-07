package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenReissueResponse(
        @NotBlank
        String accessToken,

        @NotBlank
        String refreshToken
) {
}
