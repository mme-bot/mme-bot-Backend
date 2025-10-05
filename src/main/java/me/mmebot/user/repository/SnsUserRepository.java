package me.mmebot.user.repository;

import java.util.Optional;
import me.mmebot.user.domain.SnsUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SnsUserRepository extends JpaRepository<SnsUser, Long> {

    Optional<SnsUser> findByProviderAndProviderUid(String provider, String providerUid);
}
