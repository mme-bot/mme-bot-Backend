package me.mmebot.auth.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import me.mmebot.auth.domain.EmailVerification;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {

    Optional<EmailVerification> findTopByEmailOrderBySendAtDesc(String email);

    long countByEmailAndSendAtAfter(String email, OffsetDateTime since);
}
