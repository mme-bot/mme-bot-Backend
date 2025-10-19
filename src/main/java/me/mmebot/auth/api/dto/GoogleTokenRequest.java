package me.mmebot.auth.api.dto;

import lombok.Builder;

@Builder
public record GoogleTokenRequest(
        String clientId,
        String clientSecret,
        String code,
        String redirectUri,
        String grantType,
        String refreshToken
) {}
