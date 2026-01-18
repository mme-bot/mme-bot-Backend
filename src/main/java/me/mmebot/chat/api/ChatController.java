package me.mmebot.chat.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.chat.api.dto.ChatMsgReq.CreateChatMsgReq;
import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.api.dto.ChatMsgRes.StartChatInitRes;
import me.mmebot.chat.service.ChatService;
import me.mmebot.stream.StreamContextStore;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static me.mmebot.chat.api.dto.ChatMsgReq.*;
import static me.mmebot.chat.api.dto.ChatMsgRes.*;
import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;
import static me.mmebot.stream.StreamContextContent.*;

@Slf4j
@RestController
@RequestMapping("${api.base-path}/chats")
@RequiredArgsConstructor
public class ChatController {

    private final ChatService chatService;
    private final StreamContextStore streamContextStore;

    @PostMapping("/chatSession")
    public CreateChatSessionRes createChatSession(@RequestBody @Valid CreateChatSessionReq req) {
        return chatService.createChatSession(req);
    }

    @PostMapping("/{chatSessionId}/message/start")
    public StartChatInitRes initFirstChatMsg(
            @RequestBody StartChatReq req,
            @RequestParam Long chatSessionId
    ) {
        String streamId = UUID.randomUUID().toString();

        streamContextStore.save(streamId, new FirstChatStreamContext(
                chatSessionId,
                req.userId(),
                LocalDateTime.now()
        ));

        return new StartChatInitRes(streamId);
    }

    @GetMapping(value = "/stream/message/start", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<String> firstChatStream(@RequestParam String streamId) {
        return chatService.createFirstChat(streamId);
    }

    @GetMapping("/{chatSessionId}/messages")
    public List<ChatMsg> chatMsgs(@RequestParam Long userId,
                                  @PathVariable("chatSessionId") Long chatSessionId) {
        return chatService.getChatMsgs(userId, chatSessionId);
    }

//    @PostMapping("/{chatSessionId}/message/start")
//    public StartChatRes startChat(@RequestBody @Valid StartChatReq req,
//                                  @PathVariable("chatSessionId") Long chatSessionId) {
//        return chatService.createFirstChat(chatSessionId, req);
//    }

    @PostMapping("/{chatSessionId}/messages")
    public StartChatMsgRes sendAndStreamMsg(@RequestBody @Valid CreateChatMsgReq req,
                                            @PathVariable("chatSessionId") Long chatSessionId) {
        String streamId = UUID.randomUUID().toString();

        streamContextStore.save(streamId, new ChatStreamContext(
                chatSessionId,
                req.userId(),
                req.replyToMsgId(),
                req.msg(),
                LocalDateTime.now()
        ));

        return new StartChatMsgRes(streamId);
    }

    @GetMapping(value = "/stream/message", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<String> chatStream(@RequestParam String streamId) {
        return chatService.createChatMessage(streamId);
    }
//    @PostMapping("/{chatSessionId}/messages")
//    public List<CreateChatMsgRes> sendAndStreamMsg(@RequestBody @Valid CreateChatMsgReq req,
//                                                   @PathVariable("chatSessionId") Long chatSessionId) {
//        return chatService.createChatMessage(chatSessionId, req);
//    }
}
