package me.mmebot.chat.mapper;

import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.domain.ChatMessage;
import org.springframework.stereotype.Component;

@Component
public class ChatMessageResponseMapper {

    public ChatMsg toChatMsg(ChatMessage chatMessage, String message) {
        return new ChatMsg(
                chatMessage.getSeq(),
                chatMessage.getRole(),
                message
        );
    }
}
