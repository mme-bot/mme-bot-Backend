package me.mmebot.auth.domain;

import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import me.mmebot.auth.jwt.JwtPayload;
import me.mmebot.core.domain.EncryptionContextEntity;

@Getter
@Builder
@AllArgsConstructor
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
                                  EncryptionContextEntity context,
                                  OffsetDateTime expiredAt,
                                  String ipAddress,
                                  String userAgent) {
        return AuthToken.builder()
                .userId(userId)
                .type(type)
                .token(token)
                .encryptionContext(context)
                .expiredAt(expiredAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(OffsetDateTime now) {
        return expiredAt.isBefore(now) || expiredAt.isEqual(now);
    }

    public boolean isRefreshToken() {
        return AuthTokenType.REFRESH.equals(type);
    }

    public void ensureRefreshToken() {
        if (!isRefreshToken()) {
            throw new InvalidAuthTokenTypeException(id, type);
        }
    }

    public boolean isUsableAt(OffsetDateTime now) {
        return !isRevoked() && !isExpired(now);
    }

    public void ensureUsable(OffsetDateTime now) {
        if (!isUsableAt(now)) {
            throw new UnusableAuthTokenException(id);
        }
    }

    public boolean matchesAadHash(byte[] expectedAadHash) {
        if (encryptionContext == null) {
            return false;
        }
        return java.util.Arrays.equals(encryptionContext.getAadHash(), expectedAadHash);
    }

    public void ensureMatchesPayload(JwtPayload payload, Long expectedUserId) {
        if (!java.util.Objects.equals(payload.userId(), expectedUserId)) {
            throw new AuthTokenUserMismatchException(id, expectedUserId, payload.userId());
        }

        if (payload.tokenType() != type) {
            throw new AuthTokenPayloadTypeMismatchException(id, type, payload.tokenType());
        }
    }

    public void revoke(OffsetDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }
}
