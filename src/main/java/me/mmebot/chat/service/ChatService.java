package me.mmebot.chat.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.chat.api.dto.ChatMessageRes.CreateChatMessageRes;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.domain.ChatSession;
import me.mmebot.chat.domain.ChatSessionStatus;
import me.mmebot.chat.exception.ChatException;
import me.mmebot.chat.repository.ChatMessageRepository;
import me.mmebot.chat.repository.ChatSessionRepository;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.service.DiaryService;
import me.mmebot.openai.dto.ChatMessageRole;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.user.domain.User;
import me.mmebot.user.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static me.mmebot.chat.api.dto.ChatMessageReq.*;
import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ChatService {

    private final ChatMessageRepository chatMessageRepository;
    private final ChatSessionRepository chatSessionRepository;
    private final DiaryService diaryService;
    private final UserService userService;
    private final OpenAIService openAiService;
    private final AesGcmCryptoService aesGcmCryptoService;
    private final EncryptionContextFactory encryptionContextFactory;

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
        
        saveChatSession(chatSession);
        
        log.info("Chat session initialized for diary {} by user {}", diary.getId(), user.getId());
        return new CreateChatSessionRes(chatSession.getId());
    }
    
    protected void saveChatSession(ChatSession chatSession) {
        chatSessionRepository.save(chatSession);
    }

    private Optional<ChatSession> getChatSessionByDiaryId(Long diaryId) {
        return chatSessionRepository.findByDiaryId(diaryId);
    }

    public CreateChatMessageRes createChatMessage(Long chatSessionId, CreateChatMessageReq req) {
        User user = userService.getActiveUser(req.userId());
        ChatSession chatSession = chatSessionRepository.findById(chatSessionId).orElseThrow(() -> {
            log.warn("Chat session {} not found when user {} tried to send a message", chatSessionId, user.getId());
            return ChatException.chatSessionNotFound(chatSessionId);
        });

        List<ChatMessage> chatMessageList = chatMessageRepository.findAllByChatSession(chatSession);
        if (chatMessageList.isEmpty()) {
            log.warn("Chat session {} has no messages, cannot proceed with user {}", chatSession.getId(), user.getId());
            throw ChatException.chatSessionHasNoMessages(chatSession.getId());
        }
        // seq asc 순으로 정렬
        chatMessageList.sort(Comparator.comparing(ChatMessage::getSeq));

        /**
         * 1. Prompt
         * 2. (ChatMessage)
         * ... ing
         */

        String diaryShortEnc = chatSession.getDiary().getSummaryShort();
        byte[] aad = aesGcmCryptoService.toAadBytes(user.getId().toString());
        String diaryShort = aesGcmCryptoService.decryptWithAad(diaryShortEnc, aad);

        String response = openAiService.sendChatMessage(
//                user.getBot().getScript(),
                diaryShort,
                chatMessageList,
                req.message());

        // 암호화 후, ai 와의 질답 메시지 각각 저장
        EncryptionContext context = encryptionContextFactory.createContext(aad);
        String reqMsgEnc = aesGcmCryptoService.encryptWithAad(req.message(), aad);
        String resMsgEnc = aesGcmCryptoService.encryptWithAad(response, aad);

        int msgSeq = chatMessageList.size() + 1;
        ChatMessage reqMsg = getMessage(reqMsgEnc, chatSession, msgSeq, context);
        ChatMessage resMsg = getMessage(resMsgEnc, chatSession, msgSeq + 1, context);

        saveChats(reqMsg, resMsg);
        return new CreateChatMessageRes(response);
    }

    @Transactional
    protected void saveChats(ChatMessage req, ChatMessage res) {
        saveChatMessage(req);
        saveChatMessage(res);
    }

    private void saveChatMessage(ChatMessage chatMessage) {
        chatMessageRepository.save(chatMessage);
    }

    private ChatMessage getMessage(String msg, ChatSession chatSession, int msgSeq, EncryptionContext context) {
        return new ChatMessage(
                chatSession,
                msgSeq,
                ChatMessageRole.SYSTEM,
                msg,
                context
        );
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
