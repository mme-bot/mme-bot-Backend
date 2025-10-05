package me.mmebot.bot.repository;

import java.util.Optional;
import me.mmebot.bot.domain.Bot;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BotRepository extends JpaRepository<Bot, Long> {

    Optional<Bot> findByName(String name);
}
