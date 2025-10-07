package me.mmebot.auth.service;

import jakarta.transaction.Transactional;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.domain.EmailVerification;
import me.mmebot.auth.exception.EmailVerificationException;
import me.mmebot.auth.repository.EmailVerificationRepository;
import me.mmebot.core.service.EncryptionContextFactory;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
public class EmailVerificationService {

    private static final int CODE_DIGITS = 6;
    private static final int MAX_SEND_COUNT = 10;
    private static final Duration EXPIRATION = Duration.ofMinutes(5);
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofHours(1);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final EmailVerificationRepository repository;
    private final EncryptionContextFactory encryptionContextFactory;
    private final TokenHashService tokenHashService;
    private final SecureRandom secureRandom = new SecureRandom();

    public SendEmailVerificationResult send(String email) {
        String normalizedEmail = normalizeEmail(email);
        if (!EMAIL_PATTERN.matcher(normalizedEmail).matches()) {
            throw EmailVerificationException.invalidEmailFormat();
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime threshold = now.minus(RATE_LIMIT_WINDOW);
        if (repository.countByEmailAndSendAtAfter(normalizedEmail, threshold) >= MAX_SEND_COUNT) {
            throw EmailVerificationException.rateLimited();
        }

        String code = nextCode();
        byte[] aadHash = tokenHashService.hash(normalizedEmail + ":" + code);

        EmailVerification verification = EmailVerification.builder()
                .email(normalizedEmail)
                .code(code)
                .expiredAt(now.plus(EXPIRATION))
                .encryptionContext(encryptionContextFactory.createContext(aadHash))
                .build();

        EmailVerification saved = repository.save(verification);
        return new SendEmailVerificationResult(saved.getId(), code);
    }

    public void check(Long emailVerificationId, String code) {
        EmailVerification verification = repository.findById(emailVerificationId)
                .orElseThrow(EmailVerificationException::notFound);

        OffsetDateTime now = OffsetDateTime.now();
        if (now.isAfter(verification.getExpiredAt())) {
            throw EmailVerificationException.expired();
        }
        if (!verification.getCode().equals(code.trim())) {
            throw EmailVerificationException.codeMismatch();
        }

        verification.markVerified();
    }

    @Transactional
    public EmailVerification requireVerified(Long emailVerificationId, String email) {
        EmailVerification verification = repository.findById(emailVerificationId)
                .orElseThrow(EmailVerificationException::notFound);

        OffsetDateTime now = OffsetDateTime.now();
        if (now.isAfter(verification.getExpiredAt())) {
            throw EmailVerificationException.expired();
        }
        if (!verification.isVerified()) {
            throw EmailVerificationException.notVerified();
        }
        String normalizedEmail = normalizeEmail(email);
        if (!verification.getEmail().equalsIgnoreCase(normalizedEmail)) {
            throw EmailVerificationException.emailMismatch();
        }

        return verification;
    }

    private String nextCode() {
        int bound = (int) Math.pow(10, CODE_DIGITS);
        int value = secureRandom.nextInt(bound);
        return String.format("%0" + CODE_DIGITS + "d", value);
    }

    private String normalizeEmail(String email) {
        if (email == null) {
            throw EmailVerificationException.emailRequired();
        }
        return email.trim().toLowerCase();
    }

    public record SendEmailVerificationResult(Long emailVerificationId, String code) {
    }
}
