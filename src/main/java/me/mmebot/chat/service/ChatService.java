package me.mmebot.chat.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.chat.domain.ChatSession;
import me.mmebot.chat.domain.ChatSessionStatus;
import me.mmebot.chat.exception.ChatException;
import me.mmebot.chat.repository.ChatSessionRepository;
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.service.DiaryService;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Optional;

import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ChatService {

    private final ChatSessionRepository chatSessionRepository;
    private final DiaryService diaryService;

    public CreateChatSessionRes createChatSession(CreateChatSessionReq req) {
        log.info("Request to create chat session for diary {} by user {}", req.diaryId(), req.userId());
        Diary diary = diaryService.getActiveDiary(req.diaryId());
        User user = diary.getUser();
        if (!req.userId().equals(user.getId())) {
            log.warn("User {} attempted to create chat session for diary {} owned by user {}",
                    req.userId(), diary.getId(), user.getId());
            throw ChatException.diaryOwnerMismatch(diary.getId(), req.userId(), user.getId());
        }

        /**
         * TODO 일기 쓴 당일에만 채팅 시작 가능, 당일에 채팅을 못하면 다음날에는 중단 됨, 전날까진 되게 해야하나????흠 고민... 일단은 당일만 !
         */

        LocalDate today = LocalDate.now();
        if (!diary.getDate().isEqual(today)) {
            log.warn("Diary {} is dated {}, only {} can create chat session", diary.getId(), diary.getDate(), today);
            throw ChatException.diaryNotFromToday(diary.getId(), diary.getDate(), today);
        }

        Optional<ChatSession> existingSession = getChatSessionByDiaryId(diary.getId());
        if (existingSession.isPresent()) {
            ChatSession session = existingSession.get();
            log.warn("Chat session {} already exists for diary {}", session.getId(), diary.getId());
            throw ChatException.chatSessionAlreadyExists(diary.getId(), session.getId());
        }

        ChatSession chatSession = ChatSession.builder()
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .build();

        chatSessionRepository.save(chatSession);

        log.info("Chat session initialized for diary {} by user {}", diary.getId(), user.getId());
        return new CreateChatSessionRes(chatSession.getId());
    }

    private Optional<ChatSession> getChatSessionByDiaryId(Long diaryId) {
        return chatSessionRepository.findByDiaryId(diaryId);
    }

    /**
     * 필요한 것
     * chatSessionId
     * userId
     * @return
     */
//    public ChatMessageRes sendMessage() {
//        return null;
//    }
}
