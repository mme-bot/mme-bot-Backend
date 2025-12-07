package me.mmebot.chat.exception;

import java.time.LocalDate;
import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class ChatException extends ApiException {

    private ChatException(HttpStatus status, String message, String errorCode) {
        super(status, message, errorCode);
    }

    public static ChatException diaryOwnerMismatch(Long diaryId, Long requesterUserId, Long ownerUserId) {
        return new ChatException(
                HttpStatus.FORBIDDEN,
                "User %d cannot create a chat session for diary %d owned by user %d".formatted(
                        requesterUserId,
                        diaryId,
                        ownerUserId
                ),
                "chat.diary.owner_mismatch"
        );
    }

    public static ChatException diaryNotFromToday(Long diaryId, LocalDate diaryDate, LocalDate today) {
        return new ChatException(
                HttpStatus.BAD_REQUEST,
                "Diary %d is dated %s but chat sessions can only start on %s".formatted(
                        diaryId,
                        diaryDate,
                        today
                ),
                "chat.diary.invalid_date"
        );
    }
}
