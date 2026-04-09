package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.port.in.command.session.SignInCommand;
import me.mmebot.auth.application.port.in.result.session.SignInResult;

public interface SignInUseCase {
    SignInResult signIn(SignInCommand command);
}
