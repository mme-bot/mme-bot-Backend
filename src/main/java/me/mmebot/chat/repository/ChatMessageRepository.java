package me.mmebot.chat.repository;

import java.util.List;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.domain.ChatSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ChatMessageRepository extends JpaRepository<ChatMessage, Long> {

    @Query("""
    select cm
    from ChatMessage cm
    join fetch cm.encryptionContext ec
    where cm.chatSession = :chatSession
""")
    List<ChatMessage> findAllByChatSessionWithEnc(ChatSession chatSession);
}
