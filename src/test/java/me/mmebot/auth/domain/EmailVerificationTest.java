package me.mmebot.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import me.mmebot.core.domain.EncryptionContext;
import org.junit.jupiter.api.Test;

class EmailVerificationTest {

    @Test
    void markVerified_setsVerifiedFlag() {
        EmailVerification verification = EmailVerification.builder()
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(verification.isVerified()).isFalse();

        verification.markVerified();

        assertThat(verification.isVerified()).isTrue();
    }

    @Test
    void isVerified_returnsTrueWhenBuilderSetsFlag() {
        EmailVerification verification = EmailVerification.builder()
                .email("user@example.com")
                .code("123456")
                .expiredAt(OffsetDateTime.now().plusMinutes(5))
                .verified(true)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(verification.isVerified()).isTrue();
    }
}
