package me.mmebot.auth.adapter.out.persistence;

import java.util.List;
import lombok.RequiredArgsConstructor;
import me.mmebot.auth.application.port.out.LoadUserRolesPort;
import me.mmebot.auth.application.port.out.SaveRolePort;
import me.mmebot.auth.domain.RoleEntity;
import me.mmebot.auth.domain.RoleName;
import me.mmebot.auth.repository.RoleRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RolePersistenceAdapter implements LoadUserRolesPort, SaveRolePort {

    private final RoleRepository roleRepository;

    @Override
    public List<RoleName> loadRoleNames(Long userId) {
        return roleRepository.findByUserId(userId).stream()
                .map(RoleEntity::getRoleName)
                .toList();
    }

    @Override
    public boolean exists(Long userId, RoleName roleName) {
        return roleRepository.existsByUserIdAndRoleName(userId, roleName);
    }

    @Override
    public void save(RoleEntity role) {
        roleRepository.save(role);
    }
}
