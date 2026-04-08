package me.mmebot.auth.application.port.out;

import java.util.List;
import me.mmebot.auth.domain.RoleName;

public interface LoadUserRolesPort {
    List<RoleName> loadRoleNames(Long userId);
}
