package me.mmebot.user.service;

import lombok.RequiredArgsConstructor;
import me.mmebot.user.api.dto.TestUser;
import me.mmebot.user.domain.User;
import me.mmebot.user.exception.UserException;
import me.mmebot.user.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getActiveUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> UserException.userNotFound(userId));
        if (user.isDeleted()) {
            throw UserException.userDeleted(userId);
        }
        return user;
    }

    public TestUser.TestUserRes createTestUser(TestUser.TestUserReq req) {
        User testUser = new User(req.nickname());
        userRepository.save(testUser);
        return new TestUser.TestUserRes(testUser.getId(), testUser.getNickname());
    }
}
