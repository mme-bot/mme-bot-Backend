package me.mmebot.auth.application.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.auth.application.command.SignUpCommand;
import me.mmebot.auth.application.port.in.SignUpUseCase;
import me.mmebot.auth.application.port.out.EmailProtectPort;
import me.mmebot.auth.application.port.out.EncryptionContextPort;
import me.mmebot.auth.application.port.out.LoadUserPort;
import me.mmebot.auth.application.port.out.PasswordEncodePort;
import me.mmebot.auth.application.port.out.SaveRolePort;
import me.mmebot.auth.application.port.out.SaveUserPort;
import me.mmebot.auth.domain.RoleEntity;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.exception.AuthException;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.user.domain.UserEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class SignUpService implements SignUpUseCase {

    private final LoadUserPort loadUserPort;
    private final SaveUserPort saveUserPort;
    private final EmailProtectPort emailProtectPort;
    private final EncryptionContextPort encryptionContextPort;
    private final PasswordEncodePort passwordEncodePort;
    private final SaveRolePort saveRolePort;

    @Override
    public void signUp(SignUpCommand command) {
        if (command.email() == null) {
            throw AuthException.emailRequired();
        }
        String normalizedEmail = command.email().trim().toLowerCase();

        loadUserPort.loadByNormalizedEmail(normalizedEmail).ifPresent(_ -> {
            log.warn("Sign-up failed: {} already in use", normalizedEmail);
            throw AuthException.duplicateEmail();
        });

        byte[] aadHash = emailProtectPort.aadHash(normalizedEmail);
        EmailProtectPort.EmailSecrets emailSecrets = emailProtectPort.prepare(normalizedEmail, aadHash);
        EncryptionContextEntity encryptionContext = encryptionContextPort.create(aadHash);

        UserEntity user = UserEntity.builder()
                .emailCipher(emailSecrets.emailCipher())
                .emailHash(emailSecrets.emailHash())
                .password(passwordEncodePort.encode(command.password()))
                .nickname(command.nickname().trim())
                .sns(false)
                .emailEncryptionContext(encryptionContext)
                .build();

        UserEntity saved = saveUserPort.save(user);

        if (!saveRolePort.exists(saved.getId(), RoleName.ROLE_USER)) {
            saveRolePort.save(RoleEntity.builder()
                    .user(saved)
                    .roleName(RoleName.ROLE_USER)
                    .build());
        }
        log.info("Sign-up succeeded: user {} registered", saved.getId());
    }
}
