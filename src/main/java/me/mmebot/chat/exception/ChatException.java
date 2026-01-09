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

    public static ChatException chatSessionAlreadyExists(Long diaryId, Long chatSessionId) {
        return new ChatException(
                HttpStatus.CONFLICT,
                "Chat session %d already exists for diary %d".formatted(
                        chatSessionId,
                        diaryId
                ),
                "chat.session.already_exists"
        );
    }

    public static ChatException chatSessionNotFound(Long chatSessionId) {
        return new ChatException(
                HttpStatus.NOT_FOUND,
                "Chat session %d not found".formatted(chatSessionId),
                "chat.session.not_found"
        );
    }

    public static ChatException chatMessageNotFound(Long chatMessageId) {
        return new ChatException(
                HttpStatus.NOT_FOUND,
                "Chat message %d not found".formatted(chatMessageId),
                "chat.message.not_found"
        );
    }

    public static ChatException chatSessionHasNoMessages(Long chatSessionId) {
        return new ChatException(
                HttpStatus.BAD_REQUEST,
                "Chat session %d does not contain any messages".formatted(chatSessionId),
                "chat.session.no_messages"
        );
    }

    public static ChatException chatSessionAlreadyHasMessages(Long chatSessionId) {
        return new ChatException(
                HttpStatus.CONFLICT,
                "Chat session %d already contains messages".formatted(chatSessionId),
                "chat.session.messages_exist"
        );
    }

    public static ChatException chatMessageAlreadyHasReply(Long chatMessageId) {
        return new ChatException(
                HttpStatus.CONFLICT,
                "Chat message %d already has a reply".formatted(chatMessageId),
                "chat.message.reply_exists"
        );
    }

    public static ChatException chatSessionUserMessageLimitExceeded(Long chatSessionId, int limit) {
        return new ChatException(
                HttpStatus.TOO_MANY_REQUESTS,
                "Chat session %d exceeded the user message limit of %d".formatted(chatSessionId, limit),
                "chat.session.user_message_limit_exceeded"
        );
    }

    public static ChatException chatSessionUserMismatch(Long chatSessionId, Long requesterUserId, Long ownerUserId) {
        return new ChatException(
                HttpStatus.FORBIDDEN,
                "User %d cannot access chat session %d owned by user %d".formatted(
                        requesterUserId,
                        chatSessionId,
                        ownerUserId
                ),
                "chat.session.user_mismatch"
        );
    }

    public static ChatException diaryNotFound(Long chatSessionId) {
        return new ChatException(
                HttpStatus.FORBIDDEN,
                "Chat Session Id %d Diary Not Found".formatted(
                        chatSessionId
                ),
                "chat.session.diary_not_found"
        );
    }
}
