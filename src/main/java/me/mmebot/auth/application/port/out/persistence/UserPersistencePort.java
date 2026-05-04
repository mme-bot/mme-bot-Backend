package me.mmebot.auth.application.port.out.persistence;

import java.util.Optional;
import me.mmebot.user.domain.User;
import me.mmebot.user.domain.UserEntity;

public interface UserPersistencePort {
    Optional<User> loadById(Long userId);
    Optional<User> loadByNormalizedEmail(String normalizedEmail);
    UserEntity save(UserEntity user);
}
