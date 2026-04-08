package me.mmebot.auth.application.port.out;

import java.util.Optional;
import me.mmebot.user.domain.User;

public interface LoadUserPort {
    Optional<User> loadById(Long userId);
    Optional<User> loadByNormalizedEmail(String normalizedEmail);
}
