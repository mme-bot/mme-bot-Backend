package me.mmebot.auth.domain;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.core.domain.EncryptionContextEntity;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthToken {

    private final Long id;
    private final Long userId;
    private final AuthTokenType type;
    private final String token;
    private final OffsetDateTime issuedAt;
    private final OffsetDateTime expiredAt;
    private OffsetDateTime revokedAt;
    private final String userAgent;
    private final String ipAddress;
    private final EncryptionContextEntity encryptionContext;

    public static AuthToken issue(Long userId,
                                  AuthTokenType type,
                                  String token,
                                  EncryptionContextEntity encryptionContext,
                                  OffsetDateTime expiredAt,
                                  String ipAddress,
                                  String userAgent) {
        return AuthToken.builder()
                .userId(userId)
                .type(type)
                .token(token)
                .issuedAt(OffsetDateTime.now())
                .expiredAt(expiredAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .encryptionContext(encryptionContext)
                .build();
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(OffsetDateTime now) {
        return expiredAt != null && (expiredAt.isBefore(now) || expiredAt.isEqual(now));
    }

    public void revoke(OffsetDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public void ensureRefreshToken() {
        if (type != AuthTokenType.REFRESH) {
            throw new InvalidAuthTokenTypeException(id, type);
        }
    }

    public void ensureUsable(OffsetDateTime now) {
        if (isRevoked() || isExpired(now)) {
            throw new UnusableAuthTokenException(id);
        }
    }

    public boolean matchesAadHash(byte[] aadHash) {
        return encryptionContext != null
                && Arrays.equals(aadHash, encryptionContext.getAadHash());
    }

    public void ensureMatchesPayload(JwtPayload payload, Long expectedUserId) {
        if (!Objects.equals(payload.userId(), expectedUserId)) {
            throw new AuthTokenUserMismatchException(id, expectedUserId, payload.userId());
        }
        if (payload.tokenType() != type) {
            throw new AuthTokenPayloadTypeMismatchException(id, type, payload.tokenType());
        }
    }
}
