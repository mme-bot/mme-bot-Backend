package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record TokenReissueRequest(
        @NotNull
        Long userId,

        @NotBlank
        @Size(max = 4096)
        String refreshToken
) {
}
