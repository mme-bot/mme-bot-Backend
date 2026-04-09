package me.mmebot.auth.domain;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.core.domain.EncryptionContextEntity;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class AuthToken {

    private Long id;
    private Long userId;
    private AuthTokenType type;
    private String token;
    private OffsetDateTime issuedAt;
    private OffsetDateTime expiredAt;
    private OffsetDateTime revokedAt;
    private String userAgent;
    private String ipAddress;
    private EncryptionContextEntity encryptionContext;

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
        if (encryptionContext == null) {
            return false;
        }
        return Arrays.equals(aadHash, encryptionContext.getAadHash());
    }

    public void ensureMatchesPayload(JwtPayload payload, Long expectedUserId) {
        Objects.requireNonNull(payload, "payload must not be null");

        if (!Objects.equals(payload.userId(), expectedUserId)) {
            throw new AuthTokenUserMismatchException(id, expectedUserId, payload.userId());
        }

        if (payload.tokenType() != type) {
            throw new AuthTokenPayloadTypeMismatchException(id, type, payload.tokenType());
        }
    }
}
