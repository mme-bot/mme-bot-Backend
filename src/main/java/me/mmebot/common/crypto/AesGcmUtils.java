package me.mmebot.common.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmUtils {

    private static final String AES_ALGO = "AES";
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    // GCM 태그 길이 (bit)
    private static final int GCM_TAG_LENGTH = 128;

    // 권장 IV 길이 (byte)
    private static final int IV_LENGTH = 12;

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * 256bit AES 키 생성 (테스트용)
     */
    public static byte[] generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGO);
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            return key.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate AES key", e);
        }
    }

    /**
     * AES-256-GCM 암호화
     *
     * @param plainText 평문
     * @param keyBytes  256bit 키 (32바이트)
     * @param aad       AAD(인증 전용 데이터) null 가능
     * @return base64( IV || CIPHERTEXT || TAG )
     */
    public static String encrypt(String plainText, byte[] keyBytes, byte[] aad) {
        try {
            // 키 준비
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES_ALGO);

            // IV 생성
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Cipher 생성
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // AAD 설정 (선택)
            if (aad != null) {
                cipher.updateAAD(aad);
            }

            // 암호화
            byte[] cipherTextWithTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // 결과: IV || CIPHERTEXT+TAG
            byte[] result = new byte[iv.length + cipherTextWithTag.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherTextWithTag, 0, result, iv.length, cipherTextWithTag.length);

            // Base64로 인코딩해서 반환
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt", e);
        }
    }

    /**
     * AES-256-GCM 복호화
     *
     * @param cipherTextBase64 base64( IV || CIPHERTEXT || TAG )
     * @param keyBytes         256bit 키 (32바이트)
     * @param aad              암호화 때 사용한 AAD와 동일해야 함 (null 가능)
     * @return 평문 문자열
     */
    public static String decrypt(String cipherTextBase64, byte[] keyBytes, byte[] aad) {
        try {
            byte[] cipherMessage = Base64.getDecoder().decode(cipherTextBase64);

            // 앞 IV_LENGTH 바이트는 IV
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(cipherMessage, 0, iv, 0, iv.length);

            // 나머지는 CIPHERTEXT+TAG
            int cipherTextLength = cipherMessage.length - IV_LENGTH;
            byte[] cipherTextWithTag = new byte[cipherTextLength];
            System.arraycopy(cipherMessage, IV_LENGTH, cipherTextWithTag, 0, cipherTextLength);

            // 키 준비
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES_ALGO);

            // Cipher 생성
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            // AAD 설정 (암호화 때와 동일해야 복호화 성공)
            if (aad != null) {
                cipher.updateAAD(aad);
            }

            byte[] plainBytes = cipher.doFinal(cipherTextWithTag);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt", e);
        }
    }
}
