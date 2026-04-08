package me.mmebot.auth.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import me.mmebot.common.logging.MaskedField;

public record TokenReissueRequest(
        @NotNull
        Long userId,

        @NotBlank
        @Size(max = 4096)
        @MaskedField String refreshToken
) {
}
