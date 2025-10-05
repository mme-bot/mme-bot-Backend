package me.mmebot.core.repository;

import java.util.Optional;
import me.mmebot.core.domain.EncryptionContext;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionContextRepository extends JpaRepository<EncryptionContext, Long> {

    Optional<EncryptionContext> findTopByKeyIdOrderByEncryptAtDesc(Long keyId);
}
