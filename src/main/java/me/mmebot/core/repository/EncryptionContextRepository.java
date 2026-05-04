package me.mmebot.core.repository;

import java.util.Optional;
import me.mmebot.core.domain.EncryptionContextEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionContextRepository extends JpaRepository<EncryptionContextEntity, Long> {

    Optional<EncryptionContextEntity> findTopByKeyIdOrderByEncryptAtDesc(Long keyId);
}
