package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import me.mmebot.common.logging.MaskedField;

public record CheckEmailVerificationRequest(
        @NotNull
        Long emailVerificationId,

        @NotBlank
        @Size(max = 16)
        @MaskedField String code
) {
}
