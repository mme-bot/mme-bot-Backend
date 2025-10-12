package me.mmebot.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import me.mmebot.core.domain.EncryptionContext;
import org.junit.jupiter.api.Test;

class AuthTokenTest {

    @Test
    void isExpired_returnsTrueWhenExpiredBeforeNow() {
        OffsetDateTime now = OffsetDateTime.now();
        AuthToken token = AuthToken.builder()
                .type(AuthTokenType.REFRESH)
                .expiredAt(now.minusMinutes(1))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(token.isExpired(now)).isTrue();
    }

    @Test
    void isExpired_returnsTrueWhenExpirationEqualsNow() {
        OffsetDateTime now = OffsetDateTime.now();
        AuthToken token = AuthToken.builder()
                .type(AuthTokenType.REFRESH)
                .expiredAt(now)
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(token.isExpired(now)).isTrue();
    }

    @Test
    void isExpired_returnsFalseWhenExpiresInFuture() {
        OffsetDateTime now = OffsetDateTime.now();
        AuthToken token = AuthToken.builder()
                .type(AuthTokenType.REFRESH)
                .expiredAt(now.plusMinutes(5))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(token.isExpired(now)).isFalse();
    }

    @Test
    void revoke_setsRevokedAtAndMakesTokenRevoked() {
        OffsetDateTime revokedAt = OffsetDateTime.now();
        AuthToken token = AuthToken.builder()
                .type(AuthTokenType.REFRESH)
                .expiredAt(revokedAt.plusMinutes(1))
                .encryptionContext(EncryptionContext.builder().id(1L).build())
                .build();

        assertThat(token.isRevoked()).isFalse();

        token.revoke(revokedAt);

        assertThat(token.isRevoked()).isTrue();
        assertThat(token.getRevokedAt()).isEqualTo(revokedAt);
    }
}
