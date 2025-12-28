package me.mmebot.user.repository;

import java.util.Optional;
import me.mmebot.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmailHash(String email);
    Optional<User> findByEmailCipher(String email);
}
