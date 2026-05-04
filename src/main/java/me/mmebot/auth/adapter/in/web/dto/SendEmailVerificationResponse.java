package me.mmebot.auth.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record SendEmailVerificationResponse(
        @NotNull
        Long emailVerificationId,

        @NotBlank
        @Size(max = 16)
        String code
) {
}
