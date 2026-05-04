package me.mmebot.auth.repository;

import java.util.List;
import java.util.Optional;
import me.mmebot.auth.domain.ProviderTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProviderTokenRepository extends JpaRepository<ProviderTokenEntity, Long> {

    Optional<ProviderTokenEntity> findByProviderAndClientId(String provider, String clientId);

    Optional<ProviderTokenEntity> findByProvider(String provider);
}
