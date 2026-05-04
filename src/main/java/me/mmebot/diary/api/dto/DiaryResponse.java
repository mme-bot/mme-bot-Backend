package me.mmebot.diary.api.dto;

import java.time.LocalDate;
import java.time.OffsetDateTime;

public final class DiaryResponse {

    private DiaryResponse() {
    }

    public record CreateDiaryRes(Long diaryId) {}

    public record DiaryDetail(
            Long diaryId,
            String content,
            String emotion,
            LocalDate date,
            OffsetDateTime createdAt,
            OffsetDateTime updatedAt
    ) {
    }
}
