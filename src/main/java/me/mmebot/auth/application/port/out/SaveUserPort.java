package me.mmebot.auth.application.port.out;

import me.mmebot.user.domain.UserEntity;

public interface SaveUserPort {
    UserEntity save(UserEntity user);
}
