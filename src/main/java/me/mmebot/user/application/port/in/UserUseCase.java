package me.mmebot.user.application.port.in;

import me.mmebot.user.application.port.in.command.CreateTestUserCommand;
import me.mmebot.user.application.port.in.command.GetUserBotCommand;
import me.mmebot.user.application.port.in.command.SetUserBotCommand;
import me.mmebot.user.application.port.in.result.CreateTestUserResult;
import me.mmebot.user.application.port.in.result.GetUserBotResult;

public interface UserUseCase {

    CreateTestUserResult createTestUser(CreateTestUserCommand command);

    void setUserBot(SetUserBotCommand command);

    GetUserBotResult getUserBot(GetUserBotCommand command);
}
