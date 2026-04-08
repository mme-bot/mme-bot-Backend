package me.mmebot.auth.application.port.out;

import me.mmebot.auth.domain.Role;
import me.mmebot.auth.domain.RoleName;

public interface SaveRolePort {
    boolean exists(Long userId, RoleName roleName);
    void save(Role role);
}
