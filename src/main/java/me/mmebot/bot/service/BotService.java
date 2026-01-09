package me.mmebot.bot.service;

import lombok.RequiredArgsConstructor;
import me.mmebot.bot.api.dto.BotRes.BotNameRes;
import me.mmebot.bot.repository.BotRepository;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
@RequiredArgsConstructor
public class BotService {

    private final BotRepository botRepository;

    public List<BotNameRes> getAllBot() {
        return botRepository.findAll()
                .stream()
                .map(bot -> new BotNameRes(bot.getId(), bot.getName()))
                .toList();
    }
}
