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
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Builder.Default;
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
                @UniqueConstraint(name = "uq_provider_client", columnNames = {"provider", "client_id"})
        })
public class ProviderToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "provider_token_id")
    private Long id;

    @Column(name = "provider", nullable = false, length = 50)
    private String provider;

    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "authorization_code", columnDefinition = "TEXT")
    private String authorizationCode;

    @Column(name = "access_token", columnDefinition = "TEXT")
    private String accessToken;

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Default
    @Column(name = "token_type", length = 32)
    private String tokenType = "Bearer";

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "encryption_context_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_provider_tokens_enc"))
    private EncryptionContext encryptionContext;

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

    public void applyAuthorizationCode(String encryptedCode, EncryptionContext context) {
        this.authorizationCode = encryptedCode;
        this.encryptionContext = context;
        this.active = true;
        this.errorCount = 0;
    }
}
