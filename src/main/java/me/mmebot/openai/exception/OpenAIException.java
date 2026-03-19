package me.mmebot.openai.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

/**
 * OpenAI 연동 관련 예외.
 */
public class OpenAIException extends ApiException {

    private OpenAIException(HttpStatus status, String message, String errorCode, Throwable cause) {
        super(status, message, errorCode, cause);
    }

    /**
     * 동기 완료 응답에 content 가 누락된 경우.
     */
    public static OpenAIException missingCompletionContent(String prompt, Object completion) {
        String promptSnippet = prompt == null ? "null" : abbreviate(prompt);
        String completionSnapshot = completion == null ? "null" : abbreviate(completion.toString());
        return new OpenAIException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "OpenAI completion returned without any content (promptSnippet=%s, completion=%s)".formatted(
                        promptSnippet,
                        completionSnapshot
                ),
                "openai.chat.empty_content",
                null
        );
    }

    /**
     * 직렬화 실패.
     */
    public static OpenAIException failedToSerialize(Object value, Throwable cause) {
        String serializedType = value == null ? "null" : value.getClass().getName();
        return new OpenAIException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to serialize value of type %s for OpenAI payload".formatted(serializedType),
                "openai.serialization_failed",
                cause
        );
    }

    /**
     * HTTP 상태 코드 기반 에러.
     */
    public static OpenAIException httpError(HttpStatus status, String body) {
        return new OpenAIException(
                status,
                "OpenAI HTTP error status=%d body=%s".formatted(status.value(), abbreviate(body == null ? "" : body)),
                "openai.http_error",
                null
        );
    }

    /**
     * 네트워크/클라이언트 오류.
     */
    public static OpenAIException clientError(Throwable cause) {
        return new OpenAIException(
                HttpStatus.BAD_GATEWAY,
                "OpenAI client error: %s".formatted(cause.getMessage()),
                "openai.client_error",
                cause
        );
    }

    private static String abbreviate(String value) {
        if (value.length() <= 200) {
            return value;
        }
        return value.substring(0, 200) + "...";
    }
}
