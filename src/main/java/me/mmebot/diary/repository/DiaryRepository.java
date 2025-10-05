package me.mmebot.diary.repository;

import java.time.LocalDate;
import java.util.Optional;
import me.mmebot.diary.domain.Diary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiaryRepository extends JpaRepository<Diary, Long> {

    Optional<Diary> findByUserIdAndDate(Long userId, LocalDate date);
}
