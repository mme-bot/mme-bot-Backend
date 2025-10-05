package me.mmebot.diary.repository;

import java.util.Optional;
import me.mmebot.diary.domain.DiaryChunk;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryChunkRepository extends JpaRepository<DiaryChunk, Long> {

    Optional<DiaryChunk> findByDiaryIdAndChunkIndex(Long diaryId, int chunkIndex);
}
