package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CheckEmailVerificationRequest(
        @NotNull
        Long emailVerificationId,

        @NotBlank
        @Size(max = 16)
        String code
) {
}
