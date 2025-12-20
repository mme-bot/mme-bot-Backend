package me.mmebot.chat.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.chat.api.dto.ChatMsgReq.CreateChatMsgReq;
import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.api.dto.ChatMsgRes.CreateChatMsgRes;
import me.mmebot.chat.api.dto.ChatMsgRes.StartChatRes;
import me.mmebot.chat.service.ChatService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static me.mmebot.chat.api.dto.ChatMsgReq.*;
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

    @GetMapping("/{chatSession}/messages")
    public List<ChatMsg> chatMsgs(@PathVariable("chatSessionId") Long chatSessionId) {
        return chatService.getChatMsgs(chatSessionId);
    }

    @PostMapping("/{chatSessionId}/message/start")
    public StartChatRes startChat(@RequestBody @Valid StartChatReq req, @PathVariable("chatSessionId") Long chatSessionId) {
        return chatService.createFirstChat(chatSessionId, req);
    }

    @PostMapping("/{chatSessionId}/messages")
    public List<CreateChatMsgRes> sendAndStreamMsg(@RequestBody @Valid CreateChatMsgReq req, @PathVariable("chatSessionId") Long chatSessionId) {
        return chatService.createChatMessage(chatSessionId, req);
    }
}
