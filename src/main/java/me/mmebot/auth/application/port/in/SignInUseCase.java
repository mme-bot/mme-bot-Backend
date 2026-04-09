package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.port.in.command.SignInCommand;
import me.mmebot.auth.application.port.in.result.SignInResult;

public interface SignInUseCase {
    SignInResult signIn(SignInCommand command);
}
