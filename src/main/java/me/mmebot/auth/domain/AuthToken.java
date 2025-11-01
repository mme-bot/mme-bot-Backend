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
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.auth.service.TokenHashService;
import me.mmebot.common.persistence.DatabaseNames;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.user.domain.User;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.AUTH_TOKEN, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_auth_token_user_issued_desc", columnList = "user_id, issued_at DESC")
})
public class AuthToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "auth_token_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AuthTokenType type;

    @Column(name = "token", columnDefinition = "TEXT")
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

    @Column(name = "ip_address")
    private String ipAddress;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "encryption_context_id", nullable = false)
    private EncryptionContext encryptionContext;

//    public AuthToken(User user,
//                     AuthTokenType type,
//                     String token,
//                     OffsetDateTime expiredAt,
//                     String ipAddress,
//                     String userAgent,
//                     TokenCipher tokenCipher,
//                     TokenHashService tokenHashService) {
//        this(user, type, token, expiredAt, ipAddress, userAgent, tokenCipher, tokenHashService, null);
//    }

    public AuthToken(User user,
                     AuthTokenType type,
                     String token,
                     OffsetDateTime expiredAt,
                     String ipAddress,
                     String userAgent,
                     TokenCipher tokenCipher,
                     TokenHashService tokenHashService,
                     byte[] aadHashOverride) {
        this.user = user;
        EncryptedToken encryptedToken = getEncryptedToken(
                token,
                user.getId(),
                aadHashOverride,
                tokenCipher,
                tokenHashService
        );
        this.type = type;
        this.token = encryptedToken.payload();
        this.expiredAt = expiredAt;
        this.ipAddress = ipAddress;
        this.encryptionContext = encryptedToken.context();
        this.userAgent = userAgent;
    }

    public String getDecodeToken(String tag, TokenCipher cipher, TokenHashService tokenHashService) {
        return cipher.decrypt(asEncryptedToken(this.token, this.encryptionContext, type.name()), TokenCipherSpec.of(getAad(tag), getAadHash(tag, tokenHashService)));
    }

    private EncryptedToken asEncryptedToken(String payload,
                                            EncryptionContext context,
                                            String label) {
        if (payload == null || context == null) {
            throw new TokenCipherException("No encrypted " + label + " available");
        }
        return new EncryptedToken(payload, context);
    }

    private EncryptedToken getEncryptedToken(String token,
                                             Long userId,
                                             byte[] aadHashOverride,
                                             TokenCipher tokenCipher,
                                             TokenHashService tokenHashService) {
        String tag = userId.toString();
        byte[] aadHash = aadHashOverride != null ? aadHashOverride : getAadHash(tag, tokenHashService);
        return tokenCipher.encrypt(
                token,
                TokenCipherSpec.of(
                        getAad(tag),
                        aadHash
                )
        );
    }

    private byte[] getAad(String tag) {
        return tag.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] getAadHash(String tag, TokenHashService tokenHashService) {
        return tokenHashService.hash(tag);
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
