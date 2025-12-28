package me.mmebot.user.service;

import lombok.RequiredArgsConstructor;
import me.mmebot.bot.domain.Bot;
import me.mmebot.bot.repository.BotRepository;
import me.mmebot.user.api.dto.TestUser;
import me.mmebot.user.domain.User;
import me.mmebot.user.exception.UserException;
import me.mmebot.user.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final BotRepository botRepository;
    private final UserRepository userRepository;

    public User getActiveUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserException.userNotFound(userId));
        if (user.isDeleted()) {
            throw UserException.userDeleted(userId);
        }
        return user;
    }

    public TestUser.TestUserRes createTestUser(TestUser.TestUserReq req) {
        Bot bot = botRepository.findAll().getFirst();
        User testUser = new User(req.nickname(), bot);
        userRepository.save(testUser);
        return new TestUser.TestUserRes(testUser.getId(), testUser.getNickname());
    }
}
