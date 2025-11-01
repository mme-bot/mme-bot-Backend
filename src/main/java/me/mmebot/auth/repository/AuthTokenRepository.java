package me.mmebot.auth.repository;

import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Long> {

    Optional<AuthToken> findTopByUserIdOrderByIssuedAtDesc(Long userId);

    Optional<AuthToken> findByUserIdAndEncryptionContextAadHash(Long userId, byte[] aadHash);

    // token 은 중복되지 않으므로 List(X) Optional(O)
    Optional<AuthToken> findByUserIdAndToken(Long userId, String token);
}
