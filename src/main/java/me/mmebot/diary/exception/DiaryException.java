package me.mmebot.diary.exception;

import java.time.LocalDate;
import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class DiaryException extends ApiException {

    private DiaryException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static DiaryException diaryNotFound(Long diaryId) {
        return new DiaryException(HttpStatus.NOT_FOUND,
                "Diary %d not found".formatted(diaryId),
                "diary.not_found");
    }

    public static DiaryException diaryAlreadyExists(LocalDate date) {
        return new DiaryException(HttpStatus.CONFLICT,
                "Diary already exists for date %s".formatted(date),
                "diary.duplicate_date");
    }
}
