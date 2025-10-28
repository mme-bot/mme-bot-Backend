package me.mmebot.auth.service;

import jakarta.transaction.Transactional;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.domain.EmailVerification;
import me.mmebot.auth.exception.EmailVerificationException;
import me.mmebot.auth.repository.EmailVerificationRepository;
import me.mmebot.auth.service.AuthServiceRecords.SendEmailVerificationResult;
import me.mmebot.common.mail.MailMessage;
import me.mmebot.common.mail.MailSender;
import me.mmebot.common.mail.MailSendingException;
import me.mmebot.core.service.EncryptionContextFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class EmailVerificationService {

    private static final int CODE_DIGITS = 6;
    private static final int MAX_SEND_COUNT = 10;
    private static final Duration EXPIRATION = Duration.ofMinutes(5);
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofHours(1);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final String EMAIL_TEMPLATE_LOCATION = "classpath:templates/mail/mail_code.html";
    private static final String EMAIL_SUBJECT = "[mmebot] 이메일 인증코드";

    private final EmailVerificationRepository repository;
    private final EncryptionContextFactory encryptionContextFactory;
    private final TokenHashService tokenHashService;
    private final MailSender mailSender;
    private final ResourceLoader resourceLoader;
    private final SecureRandom secureRandom = new SecureRandom();
    private volatile String cachedTemplate;

    public SendEmailVerificationResult send(String email) {
        String normalizedEmail = normalizeEmail(email);
        if (!EMAIL_PATTERN.matcher(normalizedEmail).matches()) {
            log.warn("Email verification send failed: invalid format for {}", email);
            throw EmailVerificationException.invalidEmailFormat();
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime threshold = now.minus(RATE_LIMIT_WINDOW);
        if (repository.countByEmailAndSendAtAfter(normalizedEmail, threshold) >= MAX_SEND_COUNT) {
            log.warn("Email verification send failed: rate limit exceeded for {}", normalizedEmail);
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
        sendVerificationEmail(saved.getEmail(), code);
        log.info("Email verification code generated successfully: verificationId={}", saved.getId());
        return new SendEmailVerificationResult(saved.getId(), code);
    }

    public void check(Long emailVerificationId, String code) {
        EmailVerification verification = repository.findById(emailVerificationId)
                .orElseThrow(() -> {
                    log.warn("Email verification check failed: verification {} not found", emailVerificationId);
                    return EmailVerificationException.notFound();
                });

        OffsetDateTime now = OffsetDateTime.now();
        if (now.isAfter(verification.getExpiredAt())) {
            log.warn("Email verification check failed: verification {} expired at {}", emailVerificationId,
                    verification.getExpiredAt());
            throw EmailVerificationException.expired();
        }
        if (!verification.getCode().equals(code.trim())) {
            log.warn("Email verification check failed: code mismatch for verification {}", emailVerificationId);
            throw EmailVerificationException.codeMismatch();
        }

        verification.markVerified();
        log.info("Email verification {} successfully validated", emailVerificationId);
    }

    @Transactional
    public EmailVerification requireVerified(Long emailVerificationId, String email) {
        EmailVerification verification = repository.findById(emailVerificationId)
                .orElseThrow(() -> {
                    log.warn("Email verification requirement failed: verification {} not found", emailVerificationId);
                    return EmailVerificationException.notFound();
                });

        OffsetDateTime now = OffsetDateTime.now();
        if (now.isAfter(verification.getExpiredAt())) {
            log.warn("Email verification requirement failed: verification {} expired at {}", emailVerificationId,
                    verification.getExpiredAt());
            throw EmailVerificationException.expired();
        }
        if (!verification.isVerified()) {
            log.warn("Email verification requirement failed: verification {} not yet confirmed", emailVerificationId);
            throw EmailVerificationException.notVerified();
        }
        String normalizedEmail = normalizeEmail(email);
        if (!verification.getEmail().equalsIgnoreCase(normalizedEmail)) {
            log.warn("Email verification requirement failed: email mismatch for verification {}", emailVerificationId);
            throw EmailVerificationException.emailMismatch();
        }

        log.info("Email verification {} confirmed for email {}", emailVerificationId, normalizedEmail);
        return verification;
    }

    private String nextCode() {
        int bound = (int) Math.pow(10, CODE_DIGITS);
        int value = secureRandom.nextInt(bound);
        return String.format("%0" + CODE_DIGITS + "d", value);
    }

    private String normalizeEmail(String email) {
        if (email == null) {
            log.error("Email normalization failed: email is required");
            throw EmailVerificationException.emailRequired();
        }
        return email.trim().toLowerCase();
    }

    private void sendVerificationEmail(String recipientEmail, String code) {
        String template = resolveTemplate();
        String body = template.replace("{{code}}", code);
        MailMessage message = MailMessage.html(recipientEmail, EMAIL_SUBJECT, body);
        mailSender.send(message);
    }

    private String resolveTemplate() {
        String template = cachedTemplate;
        if (template != null) {
            return template;
        }
        synchronized (this) {
            if (cachedTemplate == null) {
                cachedTemplate = loadTemplate();
            }
            return cachedTemplate;
        }
    }

    private String loadTemplate() {
        try {
            Resource resource = resourceLoader.getResource(EMAIL_TEMPLATE_LOCATION);
            if (!resource.exists()) {
                log.error("Email template not found at {}", EMAIL_TEMPLATE_LOCATION);
                throw new MailSendingException("Email verification template not found");
            }
            try (InputStreamReader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
                return FileCopyUtils.copyToString(reader);
            }
        } catch (IOException ex) {
            log.error("Failed to load email template from {}", EMAIL_TEMPLATE_LOCATION, ex);
            throw new MailSendingException("Failed to load email verification template", ex);
        }
    }
}
