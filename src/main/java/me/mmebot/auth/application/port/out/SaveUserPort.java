package me.mmebot.auth.application.port.out;

import me.mmebot.user.domain.User;

public interface SaveUserPort {
    User save(User user);
}
