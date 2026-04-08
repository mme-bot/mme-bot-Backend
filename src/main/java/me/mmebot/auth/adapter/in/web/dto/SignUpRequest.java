package me.mmebot.auth.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import me.mmebot.common.logging.MaskedField;
import me.mmebot.common.validation.ValidEmail;

public record SignUpRequest(
        @NotBlank
        @Size(max = 320)
        @ValidEmail
        String email,

        @NotBlank
        @Size(min = 8, max = 255)
        @MaskedField String passwd,

        @NotBlank
        @Size(max = 40)
        String nickname
) {
}
