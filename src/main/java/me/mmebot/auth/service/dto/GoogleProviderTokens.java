package me.mmebot.auth.service.dto;

import java.time.OffsetDateTime;

public record GoogleProviderTokens(
        String authorizationCode,
        String refreshToken,
        String accessToken,
        OffsetDateTime accessTokenExpiresAt,
        String tokenType,
        String scopes
) {
}
