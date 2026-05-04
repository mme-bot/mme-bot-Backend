package me.mmebot.auth.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import me.mmebot.auth.domain.EmailVerificationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationRepository extends JpaRepository<EmailVerificationEntity, Long> {

    Optional<EmailVerificationEntity> findTopByEmailOrderBySendAtDesc(String email);

    long countByEmailAndSendAtAfter(String email, OffsetDateTime since);
}
