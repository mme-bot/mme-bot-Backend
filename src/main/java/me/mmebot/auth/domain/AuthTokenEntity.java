package me.mmebot.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import me.mmebot.common.persistence.DatabaseNames;

import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.user.domain.UserEntity;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.AUTH_TOKEN, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_auth_token_user_issued_desc", columnList = "user_id, issued_at DESC")
})
public class AuthTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "auth_token_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 32)
    private AuthTokenType type;

    @Column(name = "token", nullable = false, columnDefinition = "TEXT")
    private String token;

    @CreationTimestamp
    @Column(name = "issued_at", nullable = false, updatable = false)
    private OffsetDateTime issuedAt;

    @Column(name = "expired_at", nullable = false)
    private OffsetDateTime expiredAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "ip_address", length = 255)
    private String ipAddress;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "encryption_context_id", nullable = false)
    private EncryptionContextEntity encryptionContext;

    public static AuthTokenEntity from(AuthToken authToken, UserEntity user) {
        return AuthTokenEntity.builder()
                .id(authToken.getId())
                .user(user)
                .type(authToken.getType())
                .token(authToken.getToken())
                .issuedAt(authToken.getIssuedAt())
                .expiredAt(authToken.getExpiredAt())
                .revokedAt(authToken.getRevokedAt())
                .userAgent(authToken.getUserAgent())
                .ipAddress(authToken.getIpAddress())
                .encryptionContext(authToken.getEncryptionContext())
                .build();
    }

    public AuthToken toModel() {
        return AuthToken.builder()
                .id(this.id)
                .userId(this.user.getId())
                .type(this.type)
                .token(this.token)
                .issuedAt(this.issuedAt)
                .expiredAt(this.expiredAt)
                .revokedAt(this.revokedAt)
                .userAgent(this.userAgent)
                .ipAddress(this.ipAddress)
                .encryptionContext(this.encryptionContext)
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
