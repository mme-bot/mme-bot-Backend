package me.mmebot.core.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.common.persistence.DatabaseNames;
import org.hibernate.annotations.JdbcTypeCode;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.ENCRYPTION_CONTEXTS, schema = DatabaseNames.Schemas.MME_BOT)
public class EncryptionContext {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "encryption_context_id")
    private Long id;

    @Lob
    @Column(name = "iv", nullable = false)
    @JdbcTypeCode(java.sql.Types.BINARY)
    private byte[] iv;

    @Lob
    @Column(name = "tag", nullable = false)
    @JdbcTypeCode (java.sql.Types.BINARY)
    private byte[] tag;

    @Lob
    @Column(name = "aad_hash", nullable = false)
    @JdbcTypeCode (java.sql.Types.BINARY)
    private byte[] aadHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_id", nullable = false)
    private EncryptionKey key;

    @Column(name = "encrypt_at")
    private OffsetDateTime encryptAt;

    public void updateTag(byte[] tag) {
        this.tag = Objects.requireNonNull(tag, "tag must not be null");
    }

    public void updateAadHash(byte[] aadHash) {
        this.aadHash = aadHash != null ? Arrays.copyOf(aadHash, aadHash.length) : null;
    }
}
