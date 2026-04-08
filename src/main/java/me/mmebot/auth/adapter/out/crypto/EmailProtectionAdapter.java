package me.mmebot.auth.adapter.out.crypto;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.EmailProtectPort;
import me.mmebot.user.service.UserEmailProtector;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EmailProtectionAdapter implements EmailProtectPort {

    private final UserEmailProtector userEmailProtector;

    @Override
    public byte[] aadHash(String normalizedEmail) {
        return userEmailProtector.aadHash(normalizedEmail);
    }

    @Override
    public EmailSecrets prepare(String normalizedEmail, byte[] aadHash) {
        UserEmailProtector.EmailSecrets secrets = userEmailProtector.prepare(normalizedEmail, aadHash);
        return new EmailSecrets(secrets.emailCipher(), secrets.emailHash(), secrets.aadHash());
    }
}
