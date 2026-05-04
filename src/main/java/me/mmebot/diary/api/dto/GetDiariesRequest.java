package me.mmebot.diary.api.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record GetDiariesRequest(
        @NotNull
        @Min(2000)
        @Max(2100)
        Integer year,

        @NotNull
        @Min(1)
        @Max(12)
        Integer month
) {
}
