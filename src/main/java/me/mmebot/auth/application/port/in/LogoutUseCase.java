package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.command.LogoutCommand;

public interface LogoutUseCase {
    void logout(LogoutCommand command);
}
