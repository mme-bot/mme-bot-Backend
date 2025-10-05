package me.mmebot.auth.repository;

import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Long> {

    Optional<AuthToken> findTopByUserIdOrderByIssuedAtDesc(Long userId);
}
