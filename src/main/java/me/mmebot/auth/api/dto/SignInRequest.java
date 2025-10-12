package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import me.mmebot.common.validation.ValidEmail;

public record SignInRequest(
        @NotBlank
        @Size(max = 320)
        @ValidEmail
        String email,

        @NotBlank
        @Size(min = 8, max = 255)
        String passwd
) {
}
