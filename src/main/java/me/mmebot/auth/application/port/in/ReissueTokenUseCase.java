package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.port.in.command.session.ReissueTokenCommand;
import me.mmebot.auth.application.port.in.result.session.TokenPairResult;

public interface ReissueTokenUseCase {
    TokenPairResult reissue(ReissueTokenCommand command);
}
