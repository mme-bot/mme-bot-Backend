package me.mmebot.auth.domain.token;

public interface TokenCipher {

    EncryptedToken encrypt(String plainText, TokenCipherSpec spec);

    String decrypt(EncryptedToken encryptedToken, TokenCipherSpec spec);
}
