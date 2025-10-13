package me.mmebot.common.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(ApiException ex, HttpServletRequest request) {
        HttpStatus status = ex.getStatus();
        ErrorResponse body = ErrorResponse.of(status.value(), status.getReasonPhrase(), ex.getMessage(), ex.getErrorCode(), request.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode statusCode,
                                                                  WebRequest request) {
        var errors = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> Map.of(
                        "field", fe.getField(),
                        "rejectedValue", fe.getRejectedValue(),
                        "message", fe.getDefaultMessage(),
                        "code", fe.getCode()
                ))
                .toList();

        String message = "Validation failed";

        ErrorResponse body = ErrorResponse.of(
                statusCode.value(),
                HttpStatus.valueOf(statusCode.value()).name(),
                errors.toString(),
                message,
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(statusCode).body(body);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, Object body, HttpHeaders headers, HttpStatusCode status, WebRequest request
    ) {
        ErrorResponse response = ErrorResponse.of(
                status.value(),
                "Error",
                ex.getMessage(),
                null,
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(status).body(response);
    }
}
