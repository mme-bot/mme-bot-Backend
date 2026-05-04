package me.mmebot.bot.repository;

import java.util.Optional;
import me.mmebot.bot.domain.BotEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BotRepository extends JpaRepository<BotEntity, Long> {

    Optional<BotEntity> findByName(String name);
}
