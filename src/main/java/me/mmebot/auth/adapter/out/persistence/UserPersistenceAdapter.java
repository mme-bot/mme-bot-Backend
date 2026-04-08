package me.mmebot.auth.adapter.out.persistence;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.LoadUserPort;
import me.mmebot.auth.application.port.out.SaveUserPort;
import me.mmebot.user.domain.UserEntity;
import me.mmebot.user.repository.UserRepository;
import me.mmebot.user.service.UserEmailProtector;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserPersistenceAdapter implements LoadUserPort, SaveUserPort {

    private final UserRepository userRepository;
    private final UserEmailProtector userEmailProtector;

    @Override
    public Optional<UserEntity> loadById(Long userId) {
        return userRepository.findById(userId);
    }

    @Override
    public Optional<UserEntity> loadByNormalizedEmail(String normalizedEmail) {
        byte[] aadHash = userEmailProtector.aadHash(normalizedEmail);
        return userRepository.findByEmailEncryptionContextAadHash(aadHash);
    }

    @Override
    public UserEntity save(UserEntity user) {
        return userRepository.save(user);
    }
}
