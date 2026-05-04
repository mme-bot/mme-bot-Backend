package me.mmebot.auth.application.port.out.persistence;

import me.mmebot.auth.domain.RoleEntity;
import me.mmebot.auth.domain.RoleName;

public interface SaveRolePort {
    boolean exists(Long userId, RoleName roleName);
    void save(RoleEntity role);
}
