package me.mmebot.chat.api.dto;

import me.mmebot.openai.dto.ChatMessageRole;

public class ChatMsgRes {
    public record StartChatRes(
            Long chatMsgId,
            String msg
    ) {}
    public record CreateChatMsgRes(
            Long chatMsgId,
            Integer seq,
            ChatMessageRole role,
            String msg
    ) {}

    public record ChatMsg(
            int seq,
            ChatMessageRole role,
            String msg
    ) {}

    public enum StreamStatus {
        LOADING,
        STREAMING,
        DONE,
        ERROR
    }

    public record ChatStreamPayload(
            StreamStatus status,
            Integer seq,
            String content,
            Long msgId,
            String message
    ) {
        public static ChatStreamPayload loading() {
            return new ChatStreamPayload(StreamStatus.LOADING, null, null, null, null);
        }

        public static ChatStreamPayload streaming(int seq, String content) {
            return new ChatStreamPayload(StreamStatus.STREAMING, seq, content, null, null);
        }

        public static ChatStreamPayload done(Long msgId) {
            return new ChatStreamPayload(StreamStatus.DONE, null, null, msgId, null);
        }

        public static ChatStreamPayload error(String message) {
            return new ChatStreamPayload(StreamStatus.ERROR, null, null, null, message);
        }
    }

    public record StartChatInitRes(
            String streamId
    ) {}

    public record StartChatMsgRes(
            String streamId
    ) {}
}
