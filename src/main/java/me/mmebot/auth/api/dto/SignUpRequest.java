package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record SignUpRequest(
        @NotBlank
        @Size(max = 320)
        String email,

        @NotBlank
        @Size(min = 8, max = 255)
        String passwd,

        @NotBlank
        @Size(max = 40)
        String nickname,

        @NotNull
        Long emailVerificationId
) {
}
