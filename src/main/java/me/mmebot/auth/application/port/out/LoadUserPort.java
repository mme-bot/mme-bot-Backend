package me.mmebot.auth.application.port.out;

import java.util.Optional;
import me.mmebot.user.domain.UserEntity;

public interface LoadUserPort {
    Optional<UserEntity> loadById(Long userId);
    Optional<UserEntity> loadByNormalizedEmail(String normalizedEmail);
}
