package me.mmebot.chat.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.chat.api.dto.ChatMsgReq.CreateChatMsgReq;
import me.mmebot.chat.api.dto.ChatMsgRes.CreateChatMsgRes;
import me.mmebot.chat.service.ChatService;
import org.springframework.web.bind.annotation.*;

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
    public CreateChatMsgRes sendAndStreamMessage(@RequestBody @Valid CreateChatMsgReq req, @PathVariable("chatSessionId") Long chatSessionId) {
        return chatService.createChatMessage(chatSessionId, req);
    }
}
