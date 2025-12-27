package me.mmebot.common.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.user.domain.User;
import me.mmebot.user.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultUserInitializer implements CommandLineRunner {

    private final EncryptionContextFactory encryptionContextFactory;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        String defaultEmail = "admin@naver.com";
        String defaultPassword = "admin123!";

        userRepository.findByEmailHash(defaultEmail).ifPresentOrElse(
                _ -> {
                    // 이미 존재하면 로그만 출력
                    log.info("기본 유저 이미 존재: " + defaultEmail);
                },
                () -> {
                    EncryptionContext context = encryptionContextFactory.createContext(defaultEmail.substring(0, 3).getBytes(StandardCharsets.UTF_8));
                    // 기본 유저 생성
                    User admin = User.builder()
                            .emailCipher(defaultEmail)
                            .password(passwordEncoder.encode(defaultPassword))
                            .nickname("admin")
                            .emailEncryptionContext(context)
                            .build();
                    userRepository.save(admin);
                    log.info("기본 계정 생성 완료");
                }
        );
    }
}
