package me.mmebot.user.api;


import lombok.RequiredArgsConstructor;
import me.mmebot.user.api.dto.SetUserBotRequest;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import me.mmebot.auth.security.SecurityUtil;
import me.mmebot.user.service.UserService;
import org.springframework.web.bind.annotation.*;

import static me.mmebot.bot.api.dto.BotRes.*;
import static me.mmebot.user.api.dto.TestUser.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/users")
public class UserController {

    private final UserService userService;

    @PostMapping
    public TestUserRes createUser(@RequestBody TestUserReq req) {
        return userService.createTestUser(req);
    }

    @PostMapping("/me/bot")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void setMyBot(@AuthenticationPrincipal UserDetails principal,
                         @Valid @RequestBody SetUserBotRequest req) {
        Long userId = SecurityUtil.extractUserId(principal);
        userService.setUserBot(userId, req.botId());
    }

    @GetMapping("/me/bot")
    public BotIdRes getMyBot(@AuthenticationPrincipal UserDetails principal) {
        Long userId = SecurityUtil.extractUserId(principal);
        return userService.getUserBot(userId);
    }
}
