package me.mmebot.user.api.dto;

public class TestUser {
    public record TestUserRes(Long userId, String nickname) {
    }

    public record TestUserReq(
            Long botId,
            String nickname
    ) {
    }
}
