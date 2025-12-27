package me.mmebot.user.api;


import lombok.RequiredArgsConstructor;
import me.mmebot.user.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}