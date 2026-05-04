package me.mmebot.auth.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenReissueResponse(
        @NotBlank
        String accessToken,

        @NotBlank
        String refreshToken
) {
}
