package me.mmebot.user.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import me.mmebot.bot.api.dto.BotRes.BotIdRes;
import me.mmebot.bot.domain.BotEntity;
import me.mmebot.bot.repository.BotRepository;
import me.mmebot.user.domain.UserEntity;
import me.mmebot.user.exception.UserException;
import me.mmebot.user.repository.UserRepository;
import org.springframework.stereotype.Service;

import static me.mmebot.user.api.dto.TestUser.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private final BotRepository botRepository;
    private final UserRepository userRepository;

    public UserEntity getActiveUser(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> UserException.userNotFound(userId));
        if (user.isDeleted()) {
            throw UserException.userDeleted(userId);
        }
        return user;
    }

    public TestUserRes createTestUser(TestUserReq req) {
        BotEntity bot = botRepository.findById(req.botId())
                .orElseThrow(() -> UserException.botNotFound(req.botId()));
        UserEntity testUser = new UserEntity(req.nickname(), bot);
        userRepository.save(testUser);
        return new TestUserRes(testUser.getId(), testUser.getNickname());
    }

    @Transactional
    public void setUserBot(Long userId, Long botId) {
        UserEntity user = getActiveUser(userId);
        BotEntity bot = botRepository.findById(botId)
                .orElseThrow(() -> UserException.botNotFound(botId));
        user.assignBot(bot);
    }

    @Transactional
    public BotIdRes getUserBot(Long userId) {
        UserEntity user = getActiveUser(userId);
        BotEntity bot = user.getBot();
        Long botId = bot == null ? null : bot.getId();
        return new BotIdRes(botId);
    }
}
