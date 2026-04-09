package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.port.in.command.ReissueTokenCommand;
import me.mmebot.auth.application.port.in.result.TokenPairResult;

public interface ReissueTokenUseCase {
    TokenPairResult reissue(ReissueTokenCommand command);
}
