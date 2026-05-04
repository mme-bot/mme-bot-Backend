package me.mmebot.user.repository;

import java.util.Optional;
import me.mmebot.user.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByEmailEncryptionContextAadHash(byte[] aadHash);
}
