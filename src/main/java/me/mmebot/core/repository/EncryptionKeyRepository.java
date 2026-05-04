package me.mmebot.core.repository;

import java.util.Optional;
import me.mmebot.core.domain.EncryptionKeyEntity;
import me.mmebot.core.domain.EncryptionKeyStatus;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionKeyRepository extends JpaRepository<EncryptionKeyEntity, Long> {

    Optional<EncryptionKeyEntity> findTopByStatusOrderByValidFromDesc(EncryptionKeyStatus status);
}
