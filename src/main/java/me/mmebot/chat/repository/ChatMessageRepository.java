package me.mmebot.chat.repository;

import java.util.Optional;
import me.mmebot.chat.domain.ChatMessage;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChatMessageRepository extends JpaRepository<ChatMessage, Long> {

    Optional<ChatMessage> findByChatSessionIdAndSeq(Long chatSessionId, int seq);
}
