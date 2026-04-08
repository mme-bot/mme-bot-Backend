package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.command.SignInCommand;
import me.mmebot.auth.application.result.SignInResult;

public interface SignInUseCase {
    SignInResult signIn(SignInCommand command);
}
