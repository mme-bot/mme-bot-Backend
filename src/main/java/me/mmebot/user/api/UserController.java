package me.mmebot.user.api;


import lombok.RequiredArgsConstructor;
import me.mmebot.user.api.dto.SetUserBotRequest;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import me.mmebot.user.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseStatus;

import static me.mmebot.user.api.dto.TestUser.*;
import static me.mmebot.user.api.dto.SetUserBotRequest.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/users")
public class UserController {

    private final UserService userService;

    @PostMapping
    public TestUserRes createUser(@RequestBody TestUserReq req) {
        return userService.createTestUser(req);
    }

    @PostMapping("/bot")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void setUserBot(@AuthenticationPrincipal Long userId,
                           @Valid @RequestBody SetUserBotRequest req) {
        userService.setUserBot(userId, req.botId());
    }
}
