package me.mmebot.user.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
import me.mmebot.bot.domain.BotEntity;
import me.mmebot.core.domain.EncryptionContextEntity;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.USERS, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_users_email", columnList = "email_hash")
})
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bot_id")
    private BotEntity bot;

    @Column(
//            nullable = false,
            length = 320, unique = true)
    private String emailHash;

    @Column(length = 320)
    private String emailCipher;

    @Column(
//            nullable = false,
            length = 255)
    private String password;

    @Column(nullable = false, length = 40)
    private String nickname;

    @Column(name = "is_sns", nullable = false)
    private boolean sns;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "email_encrypt_id"
//            , nullable = false
    )
    private EncryptionContextEntity emailEncryptionContext;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public User toModel() {
        return User.builder()
                .id(this.id)
                .botId(this.bot != null ? this.bot.getId() : null)
                .emailHash(this.emailHash)
                .emailCipher(this.emailCipher)
                .password(this.password)
                .nickname(this.nickname)
                .sns(this.sns)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .deletedAt(this.deletedAt)
                .build();
    }

    public UserEntity(String nickname, BotEntity bot) {
        this.bot = bot;
        this.createdAt = OffsetDateTime.now();
        this.sns = false;
        this.nickname = nickname;
    }

    public void assignBot(BotEntity bot) {
        this.bot = bot;
    }
}
