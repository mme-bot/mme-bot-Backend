package me.mmebot.chat.domain;

import jakarta.persistence.*;
import me.mmebot.common.persistence.DatabaseNames;
import java.time.OffsetDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.openai.dto.ChatMessageRole;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Entity
@Table(name = DatabaseNames.Tables.CHAT_MESSAGE, schema = DatabaseNames.Schemas.MME_BOT, indexes = {
        @Index(name = "idx_chat_message_session_seq", columnList = "chat_session_id, seq")
})
public class ChatMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "chat_message_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "chat_session_id", nullable = false)
    private ChatSession chatSession;

    @Column(nullable = false)
    private Integer seq;

    @Column(nullable = false, length = 16)
    @Enumerated(EnumType.STRING)
    private ChatMessageRole role;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "encryption_context_id", nullable = false)
    private EncryptionContext encryptionContext;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reply_to_message_id")
    private ChatMessage replyMsg;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public ChatMessage(ChatSession chatSession, Integer seq, ChatMessageRole role, String content, EncryptionContext encryptionContext, ChatMessage replyMsg) {
        this.chatSession = chatSession;
        this.seq = seq;
        this.role = role;
        this.content = content;
        this.createdAt = OffsetDateTime.now();
        this.encryptionContext = encryptionContext;
        this.replyMsg = replyMsg;
    }

    public ChatMessage(ChatSession chatSession, Integer seq, ChatMessageRole role, String content, EncryptionContext encryptionContext) {
        this.chatSession = chatSession;
        this.seq = seq;
        this.role = role;
        this.content = content;
        this.createdAt = OffsetDateTime.now();
        this.encryptionContext = encryptionContext;
    }

    public void updateReplyMsg(ChatMessage replyMsg) {
        this.replyMsg = replyMsg;
    }
}
