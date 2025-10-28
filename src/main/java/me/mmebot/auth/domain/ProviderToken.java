package me.mmebot.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.auth.domain.token.EncryptedToken;
import me.mmebot.auth.domain.token.TokenCipher;
import me.mmebot.auth.domain.token.TokenCipherException;
import me.mmebot.auth.domain.token.TokenCipherSpec;
import me.mmebot.common.persistence.DatabaseNames;
import me.mmebot.core.domain.EncryptionContext;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.PROVIDER_TOKENS, schema = DatabaseNames.Schemas.MME_BOT,
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_provider_client", columnNames = {"provider"})
        })
public class ProviderToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "provider_token_id")
    private Long id;

    @Column(name = "provider", nullable = false, length = 50, unique = true)
    private String provider;

    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "authorization_code", columnDefinition = "TEXT")
    private String authorizationCode;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "authorization_context_id",
            foreignKey = @ForeignKey(name = "fk_provider_tokens_authorization_ctx"))
    private EncryptionContext authorizationCodeContext;

    @Column(name = "refresh_token", columnDefinition = "TEXT")
    private String refreshToken;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "refresh_context_id",
            foreignKey = @ForeignKey(name = "fk_provider_tokens_refresh_ctx"))
    private EncryptionContext refreshTokenContext;

    @Column(name = "access_token", columnDefinition = "TEXT")
    private String accessToken;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "access_context_id",
            foreignKey = @ForeignKey(name = "fk_provider_tokens_access_ctx"))
    private EncryptionContext accessTokenContext;

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Default
    @Column(name = "token_type", length = 32)
    private String tokenType = "Bearer";

    @Column(name = "scopes", columnDefinition = "TEXT")
    private String scopes;

    @Default
    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Default
    @Column(name = "error_count", nullable = false)
    private int errorCount = 0;

    @Column(name = "last_refresh_at")
    private OffsetDateTime lastRefreshAt;

    @Column(name = "last_api_call_at")
    private OffsetDateTime lastApiCallAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public void storeAuthorizationCode(EncryptedToken encryptedToken) {
        requireToken(encryptedToken, "authorization code");
        this.authorizationCode = encryptedToken.payload();
        this.authorizationCodeContext = encryptedToken.context();
        this.active = true;
        this.errorCount = 0;
    }

    public void storeRefreshToken(EncryptedToken encryptedToken) {
        requireToken(encryptedToken, "refresh token");
        this.refreshToken = encryptedToken.payload();
        this.refreshTokenContext = encryptedToken.context();
        this.authorizationCode = null;
        this.authorizationCodeContext = null;
        this.active = true;
        this.errorCount = 0;
    }

    public void storeAccessToken(EncryptedToken encryptedToken,
                                 OffsetDateTime expiresAt,
                                 String tokenType,
                                 String scopes,
                                 OffsetDateTime refreshedAt) {
        requireToken(encryptedToken, "access token");
        this.accessToken = encryptedToken.payload();
        this.accessTokenContext = encryptedToken.context();
        this.expiresAt = expiresAt;
        if (tokenType != null && !tokenType.isBlank()) {
            this.tokenType = tokenType;
        }
        this.scopes = scopes;
        this.lastRefreshAt = refreshedAt;
        this.active = true;
        this.errorCount = 0;
    }

    public boolean hasAuthorizationCode() {
        return authorizationCode != null && authorizationCodeContext != null;
    }

    public boolean hasRefreshToken() {
        return refreshToken != null && refreshTokenContext != null;
    }

    public boolean hasAccessToken() {
        return accessToken != null && accessTokenContext != null;
    }

    public String decodeAuthorizationCode(TokenCipher cipher, TokenCipherSpec spec) {
        return cipher.decrypt(asEncryptedToken(authorizationCode, authorizationCodeContext, "authorization code"),
                specOrEmpty(spec));
    }

    public String decodeRefreshToken(TokenCipher cipher, TokenCipherSpec spec) {
        return cipher.decrypt(asEncryptedToken(refreshToken, refreshTokenContext, "refresh token"), specOrEmpty(spec));
    }

    public String decodeAccessToken(TokenCipher cipher, TokenCipherSpec spec) {
        return cipher.decrypt(asEncryptedToken(accessToken, accessTokenContext, "access token"), specOrEmpty(spec));
    }

    private void requireToken(EncryptedToken encryptedToken, String label) {
        if (encryptedToken == null) {
            throw new TokenCipherException("Encrypted " + label + " must not be null");
        }
        if (encryptedToken.payload() == null || encryptedToken.context() == null) {
            throw new TokenCipherException("Encrypted " + label + " is incomplete");
        }
    }

    private EncryptedToken asEncryptedToken(String payload,
                                            EncryptionContext context,
                                            String label) {
        if (payload == null || context == null) {
            throw new TokenCipherException("No encrypted " + label + " available");
        }
        return new EncryptedToken(payload, context);
    }

    private TokenCipherSpec specOrEmpty(TokenCipherSpec spec) {
        return spec != null ? spec : TokenCipherSpec.empty();
    }
}
