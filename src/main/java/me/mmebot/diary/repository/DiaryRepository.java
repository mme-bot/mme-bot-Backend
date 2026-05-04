package me.mmebot.diary.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import me.mmebot.diary.domain.DiaryEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryRepository extends JpaRepository<DiaryEntity, Long> {

    Optional<DiaryEntity> findByUserIdAndDateAndDeletedAtIsNull(Long userId, LocalDate date);

    Optional<DiaryEntity> findByIdAndDeletedAtIsNull(Long id);

    List<DiaryEntity> findByUserIdAndDeletedAtIsNullOrderByDateDesc(Long userId);
}
