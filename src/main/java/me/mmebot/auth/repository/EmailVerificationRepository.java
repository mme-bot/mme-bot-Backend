package me.mmebot.auth.repository;

import java.util.Optional;
import me.mmebot.auth.domain.EmailVerification;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {

    Optional<EmailVerification> findTopByEmailOrderBySendAtDesc(String email);
}
