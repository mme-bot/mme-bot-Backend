package me.mmebot.diary.repository;

import java.time.LocalDate;
import java.util.List;
import me.mmebot.diary.domain.DiaryEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface DiaryJpaRepository extends JpaRepository<DiaryEntity, Long>, DiaryRepository {

    @Override
    @Query("""
            select d
            from DiaryEntity d
            where d.user.id = :userId
              and d.date between :startDate and :endDate
              and d.deletedAt is null
            order by d.date desc
            """)
    List<DiaryEntity> findMonthlyDiaries(
            @Param("userId") Long userId,
            @Param("startDate") LocalDate startDate,
            @Param("endDate") LocalDate endDate
    );
}
