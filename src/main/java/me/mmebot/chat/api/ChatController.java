package me.mmebot.chat.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.chat.api.dto.ChatRes.CreateChatSessionRes;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.service.ChatService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static me.mmebot.chat.api.dto.ChatReq.*;

@RestController
@RequestMapping("${api.base-path}/chats")
@RequiredArgsConstructor
public class ChatController {

    private final ChatService chatService;

    @PostMapping
    public CreateChatSessionRes createChatSession(@RequestBody @Valid CreateChatSessionReq req) {
        return chatService.createChatSession(req);
    }

    @PostMapping
    public void sendAndStreamMessage(@RequestBody @Valid ChatMessage chatMessage) {

    }
}
