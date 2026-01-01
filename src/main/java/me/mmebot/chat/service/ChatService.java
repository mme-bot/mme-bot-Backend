package me.mmebot.chat.service;

import lombok.RequiredArgsConstructor;
import me.mmebot.chat.api.dto.ChatMsgRes.CreateChatMsgRes;
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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static me.mmebot.chat.api.dto.ChatMsgReq.*;
import static me.mmebot.chat.api.dto.ChatMsgRes.*;
import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;

@Service
@RequiredArgsConstructor
public class ChatService {

    private final ChatMessageRepository chatMsgRepository;
    private final ChatSessionRepository chatSessionRepository;
    private final DiaryService diaryService;
    private final UserService userService;
    private final OpenAIService openAiService;
    private final AesGcmCryptoService aesGcmCryptoService;
    private final EncryptionContextFactory encryptionContextFactory;

    public CreateChatSessionRes createChatSession(CreateChatSessionReq req) {
        Diary diary = diaryService.getActiveDiary(req.diaryId());
        User user = diary.getUser();
        if (!req.userId().equals(user.getId())) {
            throw ChatException.diaryOwnerMismatch(diary.getId(), req.userId(), user.getId());
        }

        /**
         * TODO 일기 쓴 당일에만 채팅 시작 가능, 당일에 채팅을 못하면 다음날에는 중단 됨,
         * -> 나중에는 전날까지 가능해야 할듯 왜냐? 새벽에 전날 일기 쓰는 사람도 있으니까..
         */

        LocalDate today = LocalDate.now();
        if (!diary.getDate().isEqual(today)) {
            throw ChatException.diaryNotFromToday(diary.getId(), diary.getDate(), today);
        }

        Optional<ChatSession> existingSession = getChatSessionByDiaryId(diary.getId());
        if (existingSession.isPresent()) {
            ChatSession session = existingSession.get();
            throw ChatException.chatSessionAlreadyExists(diary.getId(), session.getId());
        }

        EncryptionContext context = encryptionContextFactory.createContext(user.getId().toString());

        ChatSession chatSession = ChatSession.builder()
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .encryptionContext(context)
                .build();
        
        saveChatSession(chatSession);
        
        return new CreateChatSessionRes(chatSession.getId());
    }

    protected Optional<ChatSession> getChatSessionWithDiaryAndUserById(Long chatSessionId) {
        return chatSessionRepository.findWithDiaryAndUser(chatSessionId);
    }

    private Optional<ChatMessage> getChatMsg(Long chatMessageId) {
        return chatMsgRepository.findById(chatMessageId);
    }
    
    protected void saveChatSession(ChatSession chatSession) {
        chatSessionRepository.save(chatSession);
    }

    private Optional<ChatSession> getChatSessionByDiaryId(Long diaryId) {
        return chatSessionRepository.findByDiaryId(diaryId);
    }

    public List<CreateChatMsgRes> createChatMessage(Long chatSessionId, CreateChatMsgReq req) {
        User user = userService.getActiveUser(req.userId());
        ChatSession chatSession = getChatSessionWithDiaryAndUserById(chatSessionId)
                .orElseThrow(() -> ChatException.chatSessionNotFound(chatSessionId));

        if (!user.equals(chatSession.getDiary().getUser())) {
            throw ChatException.chatSessionUserMismatch(
                    chatSession.getId(),
                    user.getId(),
                    chatSession.getDiary().getUser().getId()
            );
        }

        ChatMessage replyMsg = getChatMsg(req.replyToMsgId())
                .orElseThrow(() -> ChatException.chatMessageNotFound(req.replyToMsgId()));

        List<ChatMessage> replyMsgs = chatMsgRepository.findAllByReplyMsgId(req.replyToMsgId());
        if (!replyMsgs.isEmpty()) {
            throw ChatException.chatMessageAlreadyHasReply(req.replyToMsgId());
        }

        List<ChatMessage> chatMsgList = getChatMessages(chatSession);
        if (chatMsgList.isEmpty()) {
            throw ChatException.chatSessionHasNoMessages(chatSession.getId());
        }
        // seq asc 순으로 정렬
        chatMsgList.sort(Comparator.comparing(ChatMessage::getSeq));

        /**
         * 1. Prompt
         * 2. (ChatMessage)
         * ... ing
         */

        String diaryShortEnc = chatSession.getDiary().getSummaryShort();
        String diaryShort = aesGcmCryptoService.decryptWithAad(diaryShortEnc, user.getId().toString());

        String response = openAiService.sendChatMessage(
//                user.getBot().getScript(),
                diaryShort,
                chatMsgList,
                req.msg());

//        String response = "테스트";
        // 암호화 후, ai 와의 질답 메시지 각각 저장
        EncryptionContext context = encryptionContextFactory.createContext(user.getId().toString());
        String reqMsgEnc = aesGcmCryptoService.encryptWithAad(req.msg(), context.getAadHash());
        String resMsgEnc = aesGcmCryptoService.encryptWithAad(response, context.getAadHash());

        ChatMessage reqMsg = getChatMessage(reqMsgEnc, chatSession, replyMsg.getSeq() + 1, context, replyMsg);
        ChatMessage resMsg = getChatMessage(resMsgEnc, chatSession, replyMsg.getSeq() + 2, context, reqMsg);

        saveChats(reqMsg, resMsg);

        return List.of(
                new CreateChatMsgRes(reqMsg.getId(), reqMsg.getSeq(), reqMsg.getRole(), req.msg()),
                new CreateChatMsgRes(resMsg.getId(), resMsg.getSeq(), resMsg.getRole(), response)
        );
    }

    @Transactional
    protected void saveChats(ChatMessage req, ChatMessage res) {
        chatMsgRepository.save(req);
        chatMsgRepository.save(res);
    }

    private List<ChatMessage> getChatMessages(ChatSession chatSession) {
        return chatMsgRepository.findAllByChatSessionWithEnc(chatSession);
    }

    private ChatMessage saveChatMessage(ChatMessage chatMsg) {
        return chatMsgRepository.save(chatMsg);
    }

    private ChatMessage getChatMessage(String msg, ChatSession chatSession, int msgSeq, EncryptionContext context) {
        return new ChatMessage(
                chatSession,
                msgSeq,
                ChatMessageRole.SYSTEM,
                msg,
                context
        );
    }

    private ChatMessage getChatMessage(String msg, ChatSession chatSession, int msgSeq, EncryptionContext context, ChatMessage replyMsg) {
        return new ChatMessage(
                chatSession,
                msgSeq,
                ChatMessageRole.SYSTEM,
                msg,
                context,
                replyMsg
        );
    }

    public StartChatRes createFirstChat(Long chatSessionId, StartChatReq req) {
        /**
         * 세션으로 첫 메시지 생성하기
         */
        User user = userService.getActiveUser(req.userId());
        ChatSession chatSession = getChatSessionWithDiaryAndUserById(chatSessionId).orElseThrow(() ->
            ChatException.chatSessionNotFound(chatSessionId));

        // 유저 검증
        if (!user.equals(chatSession.getDiary().getUser())) {
            throw ChatException.chatSessionUserMismatch(
                    chatSession.getId(),
                    user.getId(),
                    chatSession.getDiary().getUser().getId()
            );
        }

        if (!getChatMessages(chatSession).isEmpty()) {
            throw ChatException.chatSessionAlreadyHasMessages(chatSession.getId());
        }

        Diary diary = chatSession.getDiary();
        String summaryShortEnc = diary.getSummaryShort();
        EncryptionContext encryptionContext = diary.getEncryptionContext();
        String summaryShort = aesGcmCryptoService.decryptWithAad(summaryShortEnc, encryptionContext.getAadHash());

        String resMsg = openAiService.sendFirstChatMsg(summaryShort);
        EncryptionContext msgEncContext = encryptionContextFactory.createContext(user.getId().toString());
        String resMsgEnc = aesGcmCryptoService.encryptWithAad("resMsg", msgEncContext.getAadHash());

        ChatMessage chatMessage = getChatMessage(
                resMsgEnc,
                chatSession,
                1,
                msgEncContext
        );
        saveChatMessage(chatMessage);
        return new StartChatRes(chatMessage.getId(), resMsg);
    }

    /**
     * 특정 채팅에 대한 메시지 목록을 가져온다.
     * @param chatSessionId : 채팅 세션 id
     * @return
     */
    public List<ChatMsg> getChatMsgs(Long chatSessionId) {
        // TODO JWT 구현이 될 경우 userId 와 chatSession 이 가진 유저가 같은 유저인지도 검증 필요
        ChatSession chatSession = getChatSessionWithDiaryAndUserById(chatSessionId)
                .orElseThrow(() -> ChatException.chatSessionNotFound(chatSessionId));

        List<ChatMessage> chatMessages = getChatMessages(chatSession);
        if (chatMessages.isEmpty()) {
            throw ChatException.chatSessionHasNoMessages(chatSession.getId());
        }

        List<ChatMsg> chatMsgs = new ArrayList<>(chatMessages.stream().map(msg -> {
            String message = aesGcmCryptoService.decryptWithAad(msg.getContent(), msg.getEncryptionContext().getAadHash());
            return new ChatMsg(msg.getSeq(), msg.getRole(), message);
        }).toList());

        chatMsgs.sort(Comparator.comparing(ChatMsg::seq));

        return chatMsgs;
    }

    /**
     * 필요한 것
     * chatSessionId
     * userId
     * @return
     */
//    public ChatMsgRes sendMessage() {
//        return null;
//    }
}
