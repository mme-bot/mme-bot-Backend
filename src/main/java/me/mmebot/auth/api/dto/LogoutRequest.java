package me.mmebot.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import me.mmebot.common.logging.MaskedField;

public record LogoutRequest(
        @NotBlank
        @MaskedField String refreshToken
) {
}
