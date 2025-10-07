package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SendEmailVerificationRequest(
        @NotBlank
        @Size(max = 320)
        String email
) {
}
