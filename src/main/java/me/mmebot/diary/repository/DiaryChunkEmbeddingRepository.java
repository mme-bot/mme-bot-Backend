package me.mmebot.diary.repository;

import java.util.Optional;
import me.mmebot.diary.domain.DiaryChunkEmbedding;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryChunkEmbeddingRepository extends JpaRepository<DiaryChunkEmbedding, Long> {

    Optional<DiaryChunkEmbedding> findByDiaryChunkId(Long diaryChunkId);
}
