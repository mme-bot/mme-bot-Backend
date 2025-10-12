package me.mmebot.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.Optional;
import me.mmebot.auth.domain.EmailVerification;
import me.mmebot.auth.exception.EmailVerificationException;
import me.mmebot.auth.repository.EmailVerificationRepository;
import me.mmebot.auth.service.AuthServiceRecords.SendEmailVerificationResult;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceTest {

    @Mock
    private EmailVerificationRepository repository;

    @Mock
    private EncryptionContextFactory encryptionContextFactory;

    @Mock
    private TokenHashService tokenHashService;

    @InjectMocks
    private EmailVerificationService emailVerificationService;

    @Test
    void send_withInvalidEmail_throwsInvalidEmailFormat() {
        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.send("invalid-email"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        verify(repository, never()).save(any());
    }

    @Test
    void send_withNullEmail_throwsEmailRequired() {
        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.send(null));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void send_whenRateLimitExceeded_throwsRateLimited() {
        when(repository.countByEmailAndSendAtAfter(eq("user@example.com"), any())).thenReturn(10L);

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.send("user@example.com"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        verify(repository, never()).save(any());
    }

    @Test
    void send_successPersistsVerificationAndReturnsResult() {
        when(repository.countByEmailAndSendAtAfter(eq("user@example.com"), any())).thenReturn(0L);
        byte[] aadHash = new byte[]{1, 2, 3};
        when(tokenHashService.hash(any(String.class))).thenReturn(aadHash);
        EncryptionContext context = EncryptionContext.builder().id(5L).aadHash(aadHash).build();
        when(encryptionContextFactory.createContext(any(byte[].class))).thenReturn(context);
        when(repository.save(any(EmailVerification.class))).thenAnswer(invocation -> {
            EmailVerification candidate = invocation.getArgument(0);
            return EmailVerification.builder()
                    .id(42L)
                    .email(candidate.getEmail())
                    .code(candidate.getCode())
                    .expiredAt(candidate.getExpiredAt())
                    .verified(candidate.isVerified())
                    .encryptionContext(candidate.getEncryptionContext())
                    .build();
        });

        SendEmailVerificationResult result = emailVerificationService.send(" User@example.com ");

        assertThat(result.emailVerificationId()).isEqualTo(42L);
        assertThat(result.code()).hasSize(6).matches("\\d{6}");

        ArgumentCaptor<EmailVerification> verificationCaptor = ArgumentCaptor.forClass(EmailVerification.class);
        verify(repository).save(verificationCaptor.capture());
        EmailVerification saved = verificationCaptor.getValue();
        assertThat(saved.getEmail()).isEqualTo("user@example.com");
        assertThat(saved.getEncryptionContext()).isEqualTo(context);
        verify(tokenHashService).hash(saved.getEmail() + ":" + saved.getCode());
    }

    @Test
    void check_whenVerificationNotFound_throwsNotFound() {
        when(repository.findById(99L)).thenReturn(Optional.empty());

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.check(99L, "123456"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void check_whenExpired_throwsExpired() {
        EmailVerification verification = EmailVerification.builder()
                .id(1L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().minusMinutes(1))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(1L)).thenReturn(Optional.of(verification));

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.check(1L, "123456"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.GONE);
    }

    @Test
    void check_whenCodeMismatch_throwsCodeMismatch() {
        EmailVerification verification = EmailVerification.builder()
                .id(1L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(1L)).thenReturn(Optional.of(verification));

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.check(1L, " 654321 "));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void check_successMarksVerificationAsVerified() {
        EmailVerification verification = EmailVerification.builder()
                .id(1L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(1L)).thenReturn(Optional.of(verification));

        emailVerificationService.check(1L, "123456");

        assertThat(verification.isVerified()).isTrue();
    }

    @Test
    void requireVerified_whenVerificationNotFound_throwsNotFound() {
        when(repository.findById(5L)).thenReturn(Optional.empty());

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.requireVerified(5L, "user@example.com"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void requireVerified_whenExpired_throwsExpired() {
        EmailVerification verification = EmailVerification.builder()
                .id(5L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().minusMinutes(1))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(5L)).thenReturn(Optional.of(verification));

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.requireVerified(5L, "user@example.com"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.GONE);
    }

    @Test
    void requireVerified_whenNotVerified_throwsNotVerified() {
        EmailVerification verification = EmailVerification.builder()
                .id(5L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(false)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(5L)).thenReturn(Optional.of(verification));

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.requireVerified(5L, "user@example.com"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void requireVerified_whenEmailMismatch_throwsEmailMismatch() {
        EmailVerification verification = EmailVerification.builder()
                .id(5L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(5L)).thenReturn(Optional.of(verification));

        EmailVerificationException ex = assertThrows(EmailVerificationException.class,
                () -> emailVerificationService.requireVerified(5L, "other@example.com"));

        assertThat(ex.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void requireVerified_successReturnsVerification() {
        EmailVerification verification = EmailVerification.builder()
                .id(5L)
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();
        when(repository.findById(5L)).thenReturn(Optional.of(verification));

        EmailVerification result = emailVerificationService.requireVerified(5L, " User@example.com ");

        assertThat(result).isSameAs(verification);
    }
}
