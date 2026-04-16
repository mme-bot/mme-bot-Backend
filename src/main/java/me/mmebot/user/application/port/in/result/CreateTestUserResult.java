package me.mmebot.user.application.port.in.result;

public record CreateTestUserResult(
        Long userId,
        String nickname
) {
}
