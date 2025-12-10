package me.mmebot.openai.exception;

import me.mmebot.common.exception.ApiException;
import org.springframework.http.HttpStatus;

public class OpenAIException extends ApiException {

    private OpenAIException(HttpStatus status, String message, String errorCode, Throwable cause) {
        super(status, message, errorCode, cause);
    }

    public static OpenAIException missingCompletionContent() {
        return new OpenAIException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "OpenAI completion returned without any content",
                "openai.chat.empty_content",
                null
        );
    }

    public static OpenAIException failedToSerialize(Object value, Throwable cause) {
        String serializedType = value == null ? "null" : value.getClass().getName();
        return new OpenAIException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to serialize value of type %s for OpenAI payload".formatted(serializedType),
                "openai.serialization_failed",
                cause
        );
    }
}
