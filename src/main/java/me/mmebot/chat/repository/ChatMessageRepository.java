package me.mmebot.chat.repository;

import java.util.List;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.domain.ChatSession;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChatMessageRepository extends JpaRepository<ChatMessage, Long> {

    List<ChatMessage> findAllByChatSession(ChatSession chatSession);
}
