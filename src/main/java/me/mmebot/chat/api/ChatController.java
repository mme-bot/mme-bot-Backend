package me.mmebot.chat.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.chat.api.dto.ChatSessionReq;
import me.mmebot.chat.api.dto.ChatSessionRes;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.service.ChatService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;

@RestController
@RequestMapping("${api.base-path}/chats")
@RequiredArgsConstructor
public class ChatController {

    private final ChatService chatService;

    @PostMapping
    public CreateChatSessionRes createChatSession(@RequestBody @Valid CreateChatSessionReq req) {
        return chatService.createChatSession(req);
    }

    @PostMapping("/{chatSessionId}/messages")
    public void sendAndStreamMessage(@RequestBody @Valid ChatMessage chatMessage) {

    }
}
