package me.mmebot.core.repository;

import java.util.Optional;
import me.mmebot.core.domain.EncryptionKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionKeyRepository extends JpaRepository<EncryptionKey, Long> {

    Optional<EncryptionKey> findTopByStatusOrderByValidFromDesc(String status);
}
