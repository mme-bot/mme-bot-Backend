package me.mmebot.user.service;

import lombok.RequiredArgsConstructor;
import me.mmebot.bot.domain.Bot;
import me.mmebot.bot.repository.BotRepository;
import me.mmebot.user.domain.User;
import me.mmebot.user.exception.UserException;
import me.mmebot.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import jakarta.transaction.Transactional;

import static me.mmebot.user.api.dto.TestUser.*;

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

    public TestUserRes createTestUser(TestUserReq req) {
        Bot bot = botRepository.findById(req.botId())
                .orElseThrow(() -> UserException.botNotFound(req.botId()));
        User testUser = new User(req.nickname(), bot);
        userRepository.save(testUser);
        return new TestUserRes(testUser.getId(), testUser.getNickname());
    }

    @Transactional
    public void setUserBot(Long userId, Long botId) {
        User user = getActiveUser(userId);
        Bot bot = botRepository.findById(botId)
                .orElseThrow(() -> UserException.botNotFound(botId));
        user.assignBot(bot);
    }
}
