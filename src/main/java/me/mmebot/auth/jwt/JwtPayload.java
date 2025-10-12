package me.mmebot.auth.jwt;

import java.time.OffsetDateTime;
import java.util.List;
import me.mmebot.auth.domain.AuthTokenType;

public record JwtPayload(
        Long userId,
        List<String> roles,
        AuthTokenType tokenType,
        OffsetDateTime expiresAt,
        String jwtId
) {
}
