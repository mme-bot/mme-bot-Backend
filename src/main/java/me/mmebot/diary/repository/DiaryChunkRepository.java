package me.mmebot.diary.repository;

import java.util.Optional;
import me.mmebot.diary.domain.DiaryChunkEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryChunkRepository extends JpaRepository<DiaryChunkEntity, Long> {

    Optional<DiaryChunkEntity> findByDiaryIdAndChunkIndex(Long diaryId, int chunkIndex);
}
