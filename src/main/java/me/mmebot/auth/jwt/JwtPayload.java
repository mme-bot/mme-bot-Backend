package me.mmebot.auth.jwt;

import java.time.OffsetDateTime;
import java.util.List;

public record JwtPayload(
        Long userId,
        List<String> roles,
        String tokenType,
        OffsetDateTime expiresAt,
        String jwtId
) {
}
