package me.mmebot.chat.domain;

import java.util.Comparator;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ChatMessages {

    private final List<ChatMessage> messages;

    public static ChatMessages from(List<ChatMessage> messages) {
        return new ChatMessages(List.copyOf(messages));
    }

    public boolean isEmpty() {
        return messages.isEmpty();
    }

    public boolean hasMessages() {
        return !isEmpty();
    }

    public List<ChatMessage> sortedBySeq() {
        return messages.stream()
                .sorted(Comparator.comparing(ChatMessage::getSeq))
                .toList();
    }
}
