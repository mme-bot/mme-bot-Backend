package me.mmebot.user.api.dto;

import jakarta.validation.constraints.NotNull;

public record SetUserBotRequest(
        @NotNull
        Long botId
) {
}

