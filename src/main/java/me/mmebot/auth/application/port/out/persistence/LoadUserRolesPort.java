package me.mmebot.auth.application.port.out.persistence;

import java.util.List;
import me.mmebot.auth.domain.RoleName;

public interface LoadUserRolesPort {
    List<RoleName> loadRoleNames(Long userId);
}
