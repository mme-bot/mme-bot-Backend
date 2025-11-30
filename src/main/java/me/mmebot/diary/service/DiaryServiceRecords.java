package me.mmebot.diary.service;

import java.time.LocalDate;
import java.time.OffsetDateTime;

public final class DiaryServiceRecords {

    private DiaryServiceRecords() {
    }

    public record DiaryDetail(
            Long diaryId,
//            Long userId,
            String content,
            String emotion,
            LocalDate date,
            OffsetDateTime createdAt,
            OffsetDateTime updatedAt
    ) {
    }
}
