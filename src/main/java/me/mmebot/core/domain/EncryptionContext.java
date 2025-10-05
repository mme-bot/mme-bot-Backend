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
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = "encryption_contexts", schema = "mmebot")
public class EncryptionContext {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "encryption_context_id")
    private Long id;

    @Lob
    @Column(nullable = false)
    private byte[] iv;

    @Lob
    @Column(nullable = false)
    private byte[] tag;

    @Lob
    @Column(name = "aad_hash")
    private byte[] aadHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_id", nullable = false)
    private EncryptionKey key;

    @Column(name = "encrypt_at")
    private OffsetDateTime encryptAt;
}
