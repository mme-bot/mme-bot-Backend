package me.mmebot.auth.domain.token;

import java.util.Arrays;

/**
 * Options describing how a token should be encrypted/decrypted.
 */
public record TokenCipherSpec(byte[] aad, byte[] aadHash) {

    public static TokenCipherSpec empty() {
        return new TokenCipherSpec(null, null);
    }

    public static TokenCipherSpec of(byte[] aad, byte[] aadHash) {
        return new TokenCipherSpec(aad, aadHash);
    }

    public TokenCipherSpec {
        aad = aad != null ? Arrays.copyOf(aad, aad.length) : null;
        aadHash = aadHash != null ? Arrays.copyOf(aadHash, aadHash.length) : null;
    }

    public byte[] aad() {
        return aad != null ? Arrays.copyOf(aad, aad.length) : null;
    }

    public byte[] aadHash() {
        return aadHash != null ? Arrays.copyOf(aadHash, aadHash.length) : null;
    }
}
