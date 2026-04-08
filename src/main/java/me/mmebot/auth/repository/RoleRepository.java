package me.mmebot.auth.repository;

import java.util.List;
import me.mmebot.auth.domain.RoleEntity;
import me.mmebot.auth.domain.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    List<RoleEntity> findByUserId(Long userId);

    boolean existsByUserIdAndRoleName(Long userId, RoleName roleName);
}
