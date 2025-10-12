package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import me.mmebot.common.validation.ValidEmail;

public record SendEmailVerificationRequest(
        @NotBlank
        @Size(max = 320)
        @ValidEmail
        String email
) {
}
