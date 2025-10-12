package me.mmebot.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class TokenHashServiceTest {

    private final TokenHashService tokenHashService = new TokenHashService();

    @Test
    void hash_returnsSha256Digest() throws NoSuchAlgorithmException {
        String value = "test-value";

        byte[] hashed = tokenHashService.hash(value);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] expected = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        assertThat(hashed).containsExactly(expected);
    }

    @Test
    void hash_whenValueNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> tokenHashService.hash(null));
    }

    @Test
    void hash_returnsDeterministicResults() {
        byte[] first = tokenHashService.hash("value");
        byte[] second = tokenHashService.hash("value");

        assertThat(first).containsExactly(second);
        assertThat(HexFormat.of().formatHex(first)).isEqualTo(HexFormat.of().formatHex(second));
    }
}
