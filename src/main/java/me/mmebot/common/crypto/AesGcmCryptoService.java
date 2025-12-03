package me.mmebot.common.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
public class AesGcmCryptoService {
    private final byte[] keyBytes;

    public AesGcmCryptoService(
            @Value("${crypto.aes256-gcm.key-base64}") String keyBase64
    ) {
        // 환경 변수/설정에 저장된 base64 키 디코딩
        this.keyBytes = Base64.getDecoder().decode(keyBase64);
        if (keyBytes.length != 32) { // 256bit
            log.error("Invalid key length");
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }
    }

    /**
     * 문자열 암호화 (AAD 없이)
     */
//    public String encrypt(String plainText) {
//        return AesGcmUtils.encrypt(plainText, keyBytes, null);
//    }

    /**
     * 문자열 암호화 (AAD 사용)
     * 예: userId, recordId 등을 AAD로 넣어서 위변조 검출 강화
     */
    public String encryptWithAad(String plainText, byte[] aad) {
        return AesGcmUtils.encrypt(plainText, keyBytes, aad);
    }

    /**
     * 복호화 (AAD 없이)
     */
//    public String decrypt(String cipherTextBase64) {
//        return AesGcmUtils.decrypt(cipherTextBase64, keyBytes, null);
//    }

    /**
     * 복호화 (AAD 사용 — 반드시 암호화할 때의 AAD와 동일해야 함)
     */
    public String decryptWithAad(String cipherTextBase64, byte[] aad) {
        return AesGcmUtils.decrypt(cipherTextBase64, keyBytes, aad);
    }

    public byte[] toAadBytes(String aadString) {
        return aadString.getBytes(StandardCharsets.UTF_8);
    }
}
