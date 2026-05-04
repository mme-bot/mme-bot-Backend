package me.mmebot.auth.repository;

import java.util.Optional;
import me.mmebot.auth.domain.AuthTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthTokenRepository extends JpaRepository<AuthTokenEntity, Long> {

    Optional<AuthTokenEntity> findTopByUserIdOrderByIssuedAtDesc(Long userId);

    Optional<AuthTokenEntity> findByUserIdAndEncryptionContextAadHash(Long userId, byte[] aadHash);

    // token 은 중복되지 않으므로 List(X) Optional(O)
    Optional<AuthTokenEntity> findByUserIdAndToken(Long userId, String token);
}
