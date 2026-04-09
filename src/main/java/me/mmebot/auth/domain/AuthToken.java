package me.mmebot.auth.domain;

import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
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

    public void revoke(OffsetDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }
}
