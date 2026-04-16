package me.mmebot.user.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import me.mmebot.bot.domain.BotEntity;
import me.mmebot.bot.repository.BotRepository;
import me.mmebot.user.application.port.in.UserUseCase;
import me.mmebot.user.application.port.in.command.CreateTestUserCommand;
import me.mmebot.user.application.port.in.command.GetUserBotCommand;
import me.mmebot.user.application.port.in.command.SetUserBotCommand;
import me.mmebot.user.application.port.in.result.CreateTestUserResult;
import me.mmebot.user.application.port.in.result.GetUserBotResult;
import me.mmebot.user.domain.UserEntity;
import me.mmebot.user.exception.UserException;
import me.mmebot.user.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService implements UserUseCase {
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

    public CreateTestUserResult createTestUser(CreateTestUserCommand command) {
        BotEntity bot = botRepository.findById(command.botId())
                .orElseThrow(() -> UserException.botNotFound(command.botId()));
        UserEntity testUser = new UserEntity(command.nickname(), bot);
        userRepository.save(testUser);
        return new CreateTestUserResult(testUser.getId(), testUser.getNickname());
    }

    @Transactional
    public void setUserBot(SetUserBotCommand command) {
        UserEntity user = getActiveUser(command.userId());
        BotEntity bot = botRepository.findById(command.botId())
                .orElseThrow(() -> UserException.botNotFound(command.botId()));
        user.assignBot(bot);
    }

    @Transactional
    public GetUserBotResult getUserBot(GetUserBotCommand command) {
        UserEntity user = getActiveUser(command.userId());
        BotEntity bot = user.getBot();
        Long botId = bot == null ? null : bot.getId();
        return new GetUserBotResult(botId);
    }
}
