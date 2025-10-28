package me.mmebot.auth.repository;

import java.util.List;
import java.util.Optional;
import me.mmebot.auth.domain.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Long> {

    Optional<AuthToken> findTopByUserIdOrderByIssuedAtDesc(Long userId);

    Optional<AuthToken> findByUserIdAndEncryptionContextAadHash(Long userId, byte[] aadHash);


    List<AuthToken> findByUserIdAndToken(Long userId, String token);
}
