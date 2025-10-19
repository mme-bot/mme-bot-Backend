package me.mmebot.auth.repository;

import java.util.Optional;
import me.mmebot.auth.domain.ProviderToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProviderTokenRepository extends JpaRepository<ProviderToken, Long> {

    Optional<ProviderToken> findByProviderAndClientId(String provider, String clientId);
}
