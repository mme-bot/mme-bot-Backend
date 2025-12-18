package me.mmebot.chat.repository;

import java.util.Optional;
import me.mmebot.chat.domain.ChatSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ChatSessionRepository extends JpaRepository<ChatSession, Long> {

    Optional<ChatSession> findByDiaryId(Long diaryId);
    @Query("""
select cs from ChatSession cs
join fetch cs.diary d
join fetch d.user
where cs.id = :id
""")
    Optional<ChatSession> findWithDiaryAndUser(Long id);

}
