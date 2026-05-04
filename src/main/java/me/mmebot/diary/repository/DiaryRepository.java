package me.mmebot.diary.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import me.mmebot.diary.domain.DiaryEntity;

public interface DiaryRepository {

    DiaryEntity save(DiaryEntity diary);

    Optional<DiaryEntity> findByUserIdAndDateAndDeletedAtIsNull(Long userId, LocalDate date);

    Optional<DiaryEntity> findByIdAndDeletedAtIsNull(Long id);

    List<DiaryEntity> findMonthlyDiaries(
            Long userId,
            LocalDate startDate,
            LocalDate endDate
    );
}
