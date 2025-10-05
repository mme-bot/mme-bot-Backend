package me.mmebot.chat.repository;

import java.util.Optional;
import me.mmebot.chat.domain.ChatSession;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChatSessionRepository extends JpaRepository<ChatSession, Long> {

    Optional<ChatSession> findByDiaryId(Long diaryId);
}
