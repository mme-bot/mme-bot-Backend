package me.mmebot.user.api;


import lombok.RequiredArgsConstructor;
import me.mmebot.user.api.dto.SetUserBotRequest;
import me.mmebot.user.application.port.in.UserUseCase;
import me.mmebot.user.application.port.in.command.CreateTestUserCommand;
import me.mmebot.user.application.port.in.command.GetUserBotCommand;
import me.mmebot.user.application.port.in.command.SetUserBotCommand;
import me.mmebot.user.application.port.in.result.CreateTestUserResult;
import me.mmebot.user.application.port.in.result.GetUserBotResult;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import me.mmebot.auth.security.SecurityUtil;
import org.springframework.web.bind.annotation.*;

import static me.mmebot.bot.api.dto.BotRes.*;
import static me.mmebot.user.api.dto.TestUser.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/users")
public class UserController {

    private final UserUseCase userUseCase;

    @PostMapping
    public TestUserRes createUser(@RequestBody TestUserReq req) {
        CreateTestUserResult result = userUseCase.createTestUser(new CreateTestUserCommand(
                req.botId(),
                req.nickname()
        ));
        return new TestUserRes(result.userId(), result.nickname());
    }

    @PostMapping("/me/bot")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void setMyBot(@AuthenticationPrincipal UserDetails principal,
                         @Valid @RequestBody SetUserBotRequest req) {
        Long userId = SecurityUtil.extractUserId(principal);
        userUseCase.setUserBot(new SetUserBotCommand(userId, req.botId()));
    }

    @GetMapping("/me/bot")
    public BotIdRes getMyBot(@AuthenticationPrincipal UserDetails principal) {
        Long userId = SecurityUtil.extractUserId(principal);
        GetUserBotResult result = userUseCase.getUserBot(new GetUserBotCommand(userId));
        return new BotIdRes(result.botId());
    }
}
