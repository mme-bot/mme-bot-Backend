package me.mmebot.diary.repository;

import java.util.Optional;
import me.mmebot.diary.domain.DiaryChunkEmbeddingEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryChunkEmbeddingRepository extends JpaRepository<DiaryChunkEmbeddingEntity, Long> {

    Optional<DiaryChunkEmbeddingEntity> findByDiaryChunkId(Long diaryChunkId);
}
