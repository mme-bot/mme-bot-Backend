package me.mmebot.auth.application.port.in;

import me.mmebot.auth.application.command.ReissueTokenCommand;
import me.mmebot.auth.application.result.TokenPairResult;

public interface ReissueTokenUseCase {
    TokenPairResult reissue(ReissueTokenCommand command);
}
