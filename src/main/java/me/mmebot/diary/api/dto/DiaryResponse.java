package me.mmebot.diary.api.dto;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import me.mmebot.diary.service.DiaryServiceRecords.DiaryDetail;

public record DiaryResponse(
        Long diaryId,
        String content,
        String emotion,
        LocalDate date,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {

    public static DiaryResponse from(DiaryDetail detail) {
        return new DiaryResponse(
                detail.diaryId(),
                detail.content(),
                detail.emotion(),
                detail.date(),
                detail.createdAt(),
                detail.updatedAt()
        );
    }
}
