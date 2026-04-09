package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.port.in.command.SignUpCommand;

public interface SignUpUseCase {
    void signUp(SignUpCommand command);
}
