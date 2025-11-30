package me.mmebot.diary.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;

public record CreateDiaryRequest(
        @NotNull
        Long userId,

        @NotBlank
        String content,

        @NotBlank
        @Size(max = 32)
        String emotion,

        @NotNull
        LocalDate date
) {
}
