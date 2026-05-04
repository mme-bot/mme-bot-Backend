package me.mmebot.diary.api.dto;

import java.time.LocalDate;
import java.time.OffsetDateTime;

public final class DiaryResponse {

    private DiaryResponse() {
    }

    public record CreateDiaryRes(Long diaryId) {}

    public record DiaryListItem(
            Long diaryId,
            String emotion,
            LocalDate date
    ) {
    }
}
