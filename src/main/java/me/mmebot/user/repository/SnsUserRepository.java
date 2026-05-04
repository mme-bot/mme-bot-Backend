package me.mmebot.user.repository;

import java.util.Optional;
import me.mmebot.user.domain.SnsUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SnsUserRepository extends JpaRepository<SnsUserEntity, Long> {

    Optional<SnsUserEntity> findByProviderAndProviderUid(String provider, String providerUid);
}
