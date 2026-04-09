package me.mmebot.auth.application.port.out.crypto;

import java.util.Arrays;

public interface EmailProtectPort {
    byte[] aadHash(String normalizedEmail);
    EmailSecrets prepare(String normalizedEmail, byte[] aadHash);

    record EmailSecrets(String emailCipher, String emailHash, byte[] aadHash) {
        public EmailSecrets {
            aadHash = aadHash != null ? Arrays.copyOf(aadHash, aadHash.length) : null;
        }
    }
}
