package me.mmebot.bot.repository;

import java.util.Optional;
import me.mmebot.bot.domain.BotImageEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BotImageRepository extends JpaRepository<BotImageEntity, Long> {

    Optional<BotImageEntity> findByBotIdAndMood(Long botId, String mood);
}
