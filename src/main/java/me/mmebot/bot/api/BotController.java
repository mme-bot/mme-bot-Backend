package me.mmebot.bot.api;


import lombok.RequiredArgsConstructor;
import me.mmebot.bot.api.dto.BotRes.BotNameRes;
import me.mmebot.bot.service.BotService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/bots")
public class BotController {

    private final BotService botService;

    @GetMapping
    public List<BotNameRes> getAllBot() {
        return botService.getAllBot();
    }
}