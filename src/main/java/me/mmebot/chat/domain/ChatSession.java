package me.mmebot.chat.domain;

import jakarta.persistence.*;
import me.mmebot.common.persistence.DatabaseNames;
import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.bot.domain.Bot;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.diary.domain.Diary;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.CHAT_SESSION, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_chat_session_diary_id", columnList = "diary_id", unique = true)
})
public class ChatSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "chat_session_id")
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "diary_id", nullable = false, unique = true)
    private Diary diary;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bot_id", nullable = false)
    private Bot bot;

    @Column(nullable = false, length = 32)
    @Enumerated(EnumType.STRING)
    private ChatSessionStatus status;

    @Column(name = "send_count", nullable = false)
    private int sendCount;

    // 대화 끝난 후, 대화 요약
    @Column(columnDefinition = "TEXT")
    private String summary;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "encryption_context_id", nullable = false)
    private EncryptionContext encryptionContext;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;
}
