package me.mmebot.bot.repository;

import java.util.Optional;
import me.mmebot.bot.domain.BotImage;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BotImageRepository extends JpaRepository<BotImage, Long> {

    Optional<BotImage> findByBotIdAndMood(Long botId, String mood);
}
