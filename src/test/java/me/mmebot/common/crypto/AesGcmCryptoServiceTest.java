package me.mmebot.common.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmCryptoServiceTest {

    private AesGcmCryptoService service;

    @BeforeEach
    void setUp() throws IOException {
        Properties props = new Properties();
        try (InputStream is = getClass()
                .getClassLoader()
                .getResourceAsStream("application.yml")) {

            props.load(is);
        }

        byte[] fixedKey = Base64.getDecoder().decode(props.getProperty("key-base64"));
        String keyBase64 = Base64.getEncoder().encodeToString(fixedKey);
        service = new AesGcmCryptoService(keyBase64);
    }

    @Test
    void encryptWithStringAad_thenDecrypt_recoversPlainText() {
        String plainText = "mmebot-secret";
        String aad = "user-42";

        String cipherText = service.encryptWithAad(plainText, aad);
        String decrypted = service.decryptWithAad(cipherText, aad);

        assertThat(cipherText).isNotEqualTo(plainText);
        assertThat(decrypted).isEqualTo(plainText);
    }

    @Test
    void encryptWithByteAad_thenDecryptWithByteAad_recoversPlainText() {
        String plainText = "diary-content";
        byte[] aadBytes = "aad-seed".getBytes(StandardCharsets.UTF_8);

        String cipherText = service.encryptWithAad(plainText, aadBytes);
        String decrypted = service.decryptWithAad(cipherText, aadBytes);

        assertThat(decrypted).isEqualTo(plainText);
    }

    @Test
    void decryptWithDifferentAad_throwsException() {
        String cipherText = service.encryptWithAad("payload", "aad-A");

        assertThatThrownBy(() -> service.decryptWithAad(cipherText, "aad-B"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to decrypt");
    }
}
