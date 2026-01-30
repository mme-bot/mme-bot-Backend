package me.mmebot.chat.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.bot.domain.Bot;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.domain.ChatSession;
import me.mmebot.chat.domain.ChatSessionStatus;
import me.mmebot.chat.domain.ChatStatus;
import me.mmebot.chat.exception.ChatException;
import me.mmebot.chat.queue.ChatPersistenceQueueService;
import me.mmebot.chat.repository.ChatMessageRepository;
import me.mmebot.chat.repository.ChatSessionRepository;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.service.DiaryService;
import me.mmebot.openai.dto.ChatMessageRole;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.stream.StreamContextStore;
import me.mmebot.user.domain.User;
import me.mmebot.user.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static me.mmebot.chat.api.dto.ChatMsgRes.*;
import static me.mmebot.chat.api.dto.ChatSessionReq.*;
import static me.mmebot.chat.api.dto.ChatSessionRes.*;
import static me.mmebot.stream.StreamContextContent.*;

@Slf4j
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
    private final StreamContextStore streamContextStore;
    private final ChatPersistenceQueueService chatPersistenceQueueService;

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

    public Flux<ChatStreamPayload> createChatMessage(String streamId) {
        ChatStreamContext streamContext = (ChatStreamContext) streamContextStore.get(streamId);

        Long userId = streamContext.userId();
        Long chatSessionId = streamContext.chatSessionId();
        Long replyToMsgId = streamContext.replyToMsgId();
        String msg = streamContext.msg();

        User user = userService.getActiveUser(userId);
        ChatSession chatSession = getChatSessionWithDiaryAndUserById(chatSessionId)
                .orElseThrow(() -> ChatException.chatSessionNotFound(chatSessionId));

        if (!user.equals(chatSession.getDiary().getUser())) {
            throw ChatException.chatSessionUserMismatch(
                    chatSession.getId(),
                    user.getId(),
                    chatSession.getDiary().getUser().getId()
            );
        }

        ChatMessage replyMsg = getChatMsg(replyToMsgId)
                .orElseThrow(() -> ChatException.chatMessageNotFound(replyToMsgId));

        List<ChatMessage> replyMsgs = chatMsgRepository.findAllByReplyMsgId(replyToMsgId);
        if (!replyMsgs.isEmpty()) {
            throw ChatException.chatMessageAlreadyHasReply(replyToMsgId);
        }

        List<ChatMessage> chatMsgList = getChatMessages(chatSession);
        if (chatMsgList.isEmpty()) {
            throw ChatException.chatSessionHasNoMessages(chatSession.getId());
        }
        long userMsgCount = chatMsgList.stream()
                .filter(ChatMessage::isUserMsg)
                .count();
        if (userMsgCount >= 21) {
            throw ChatException.chatSessionUserMessageLimitExceeded(chatSession.getId(), 20);
        }
        // seq asc 순으로 정렬
        chatMsgList.sort(Comparator.comparing(ChatMessage::getSeq));

        /**
         * 1. Prompt
         * 2. (ChatMessage)
         * ... ing
         */

        ChatStatus chatStatus = ChatStatus.IN_PROGRESS;
        if (userMsgCount >= 19) {
            chatStatus = ChatStatus.FINAL;
        }

        Diary diary = chatSession.getDiary();
//        String diaryShortEnc = diary.getSummaryShort();
        StringBuilder fullMsg = new StringBuilder();
        final int userMessageSeq = replyMsg.getSeq() + 1;
        final int assistantMessageSeq = userMessageSeq + 1;

        AtomicReference<Long> savedMsgIdRef = new AtomicReference<>();
        AtomicInteger chunkSeq = new AtomicInteger();

        Flux<String> aiStream = openAiService.sendChatMessage(
                user.getBot().getPersona(),
                user.getBot().getScript(),
                chatStatus.name(),
                diary.getEmotion(),
                chatMsgList,
                msg,
                user.getNickname())
                .doOnNext(fullMsg::append) // 토큰 누적
                .doOnComplete(() -> {
                    ChatMessage savedAssistantMsg = saveChatMessagePair(chatSession, user, replyMsg, msg, fullMsg.toString());
                    setSavedMsgId(
                            savedMsgIdRef,
                            savedAssistantMsg,
                            "Assistant message was not persisted for streamId=" + streamId
                    );
                })
                .doOnError(throwable -> {
                    chatPersistenceQueueService.enqueueChatMessagePairFallback(
                            chatSession.getId(),
                            user.getId(),
                            replyMsg.getId(),
                            userMessageSeq,
                            assistantMessageSeq,
                            msg,
                            fullMsg.toString(),
                            throwable
                    );
                })
                .doFinally( doOnFinally ->
                        streamContextStore.remove(streamId)
                );


        log.info("bot msg : {}", fullMsg);
        Flux<ChatStreamPayload> streamingResponses = aiStream.map(chunk -> ChatStreamPayload.streaming(chunkSeq.incrementAndGet(), chunk));

        return Flux.concat(
                        Flux.just(ChatStreamPayload.loading()),
                        streamingResponses,
                        Flux.defer(() -> Flux.just(
                                buildDoneSignal(
                                        savedMsgIdRef,
                                        "Assistant message ID missing for streamId=" + streamId
                                )
                        ))
                ).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> Flux.just(buildErrorPayload(e.getMessage())));
    }

    public ChatMessage saveChatMessagePair(
            ChatSession chatSession,
            User user,
            ChatMessage replyMsg,
            String userMsg,
            String botMsg
    ) {
        int userSeq = replyMsg.getSeq() + 1;
        int assistantSeq = userSeq + 1;
        if (chatMsgRepository.existsByChatSessionIdAndSeq(chatSession.getId(), userSeq)
                || chatMsgRepository.existsByChatSessionIdAndSeq(chatSession.getId(), assistantSeq)) {
            log.debug("Chat message pair already exists for session {} seqs [{}, {}] - skipping",
                    chatSession.getId(),
                    userSeq,
                    assistantSeq);
            return chatMsgRepository.findByChatSessionIdAndSeq(chatSession.getId(), assistantSeq).orElse(null);
        }

        EncryptionContext context = encryptionContextFactory.createContext(user.getId().toString());
        String reqMsgEnc = aesGcmCryptoService.encryptWithAad(userMsg, context.getAadHash());
        String resMsgEnc = aesGcmCryptoService.encryptWithAad(botMsg, context.getAadHash());

        ChatMessage reqMsg = getChatMessage(
                reqMsgEnc,
                chatSession,
                userSeq,
                ChatMessageRole.USER,
                context,
                replyMsg
        );
        ChatMessage resMsg = getChatMessage(
                resMsgEnc,
                chatSession,
                assistantSeq,
                ChatMessageRole.ASSISTANT,
                context,
                reqMsg
        );

        saveChats(reqMsg, resMsg);
        return resMsg;
    }

    @Transactional
    protected void saveChats(ChatMessage req, ChatMessage res) {
        chatMsgRepository.save(req);
        chatMsgRepository.save(res);
    }

    private String renderMsgUserToNickname(String msg, String nickname) {
        return msg.replace("{user}", nickname);
    }

    private List<ChatMessage> getChatMessages(ChatSession chatSession) {
        return chatMsgRepository.findAllByChatSessionWithEnc(chatSession);
    }

    private ChatMessage saveChatMessage(ChatMessage chatMsg) {
        return chatMsgRepository.save(chatMsg);
    }

    private ChatMessage getChatMessage(
            String msg,
            ChatSession chatSession,
            int msgSeq,
            ChatMessageRole role,
            EncryptionContext context,
            ChatMessage replyMsg
    ) {
        return new ChatMessage(
                chatSession,
                msgSeq,
                role,
                msg,
                context,
                replyMsg
        );
    }

    public Flux<ChatStreamPayload> createFirstChat(String streamId) {
        /**
         * 세션으로 첫 메시지 생성하기
         */
        FirstChatStreamContext streamContext = (FirstChatStreamContext) streamContextStore.get(streamId);
        if (streamContext == null) {
            return Flux.just(buildErrorPayload("INVALID_STREAM"));
        }
        Long chatSessionId = streamContext.chatSessionId();
        Long userId = streamContext.userId();

        User user = userService.getActiveUser(userId);
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
//        String summaryShortEnc = diary.getSummaryShort();
        String contentEnc = diary.getContent();
        EncryptionContext encryptionContext = diary.getEncryptionContext();
        String content = aesGcmCryptoService.decryptWithAad(contentEnc, encryptionContext.getAadHash());

        Bot bot = user.getBot();
        StringBuilder fullMsg = new StringBuilder();
        final int firstMessageOrder = 1;

        AtomicReference<Long> savedMsgIdRef = new AtomicReference<>();
        AtomicInteger chunkSeq = new AtomicInteger();

//        String resMsg = openAiService.sendFirstChatMsg(
        Flux<String> aiStream = openAiService.sendFirstChatMsg(
                bot.getPersona(),
                bot.getScript(),
                diary.getEmotion(),
                content,
                user.getNickname())
                .doOnNext(fullMsg::append) // 토큰 누적
                .doOnComplete(() -> {
                    // 3. 스트림 끝난 뒤 DB 저장 (⭐ 중요)
                    ChatMessage savedMsg = saveFirstMessage(chatSession, user, fullMsg.toString());
                    setSavedMsgId(
                            savedMsgIdRef,
                            savedMsg,
                            "First assistant message was not persisted for streamId=" + streamId
                    );
                })
                .doOnError(throwable -> {
                    chatPersistenceQueueService.enqueueFirstMessageFallback(
                            chatSession.getId(),
                            user.getId(),
                            firstMessageOrder,
                            fullMsg.toString(),
                            throwable
                    );
                })
                .doFinally( doOnFinally ->
                        streamContextStore.remove(streamId)
                );

        Flux<ChatStreamPayload> streamingResponses = aiStream.map(chunk -> ChatStreamPayload.streaming(chunkSeq.incrementAndGet(), chunk));

        return Flux.concat(
                        Flux.just(ChatStreamPayload.loading()),
                        streamingResponses,
                        Flux.defer(() -> Flux.just(
                                buildDoneSignal(
                                        savedMsgIdRef,
                                        "First assistant message ID missing for streamId=" + streamId
                                )
                        ))
                ).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> Flux.just(buildErrorPayload(e.getMessage())));
    }

    public ChatMessage saveFirstMessage(ChatSession chatSession, User user, String resMsg) {
        final int messageOrder = 1;
        if (chatMsgRepository.existsByChatSessionIdAndSeq(chatSession.getId(), messageOrder)) {
            log.debug("First chat message already exists for session {} - skipping", chatSession.getId());
            return chatMsgRepository.findByChatSessionIdAndSeq(chatSession.getId(), messageOrder).orElse(null);
        }
        EncryptionContext msgEncContext = encryptionContextFactory.createContext(user.getId().toString());
        String resMsgEnc = aesGcmCryptoService.encryptWithAad(resMsg, msgEncContext.getAadHash());

        ChatMessage chatMessage = getChatMessage(
                resMsgEnc,
                chatSession,
                messageOrder,
                ChatMessageRole.ASSISTANT,
                msgEncContext,
                null
        );
        return saveChatMessage(chatMessage);
    }

    private void setSavedMsgId(AtomicReference<Long> savedMsgIdRef, ChatMessage savedMsg, String errorMessage) {
        if (savedMsg == null || savedMsg.getId() == null) {
            throw new IllegalStateException(errorMessage);
        }
        savedMsgIdRef.set(savedMsg.getId());
    }

    private Long requireSavedMsgId(AtomicReference<Long> savedMsgIdRef, String errorMessage) {
        Long messageId = savedMsgIdRef.get();
        if (messageId == null) {
            throw new IllegalStateException(errorMessage);
        }
        return messageId;
    }

    private ChatStreamPayload buildDoneSignal(AtomicReference<Long> savedMsgIdRef, String errorMessage) {
        Long msgId = requireSavedMsgId(savedMsgIdRef, errorMessage);
        return ChatStreamPayload.done(msgId);
    }

    private ChatStreamPayload buildErrorPayload(String message) {
        return ChatStreamPayload.error("문제가 발생했어요." + message);
    }

    /**
     * 특정 채팅에 대한 메시지 목록을 가져온다.
     * @param chatSessionId : 채팅 세션 id
     * @return
     */
//    public List<ChatMsg> getChatMsgs(Long chatSessionId) {
    public List<ChatMsg> getChatMsgs(Long userId, Long chatSessionId) {
        // TODO JWT 구현이 없으니 일단 userId 를 uri 로 받아서 검증하는 걸로, JWT 나오면 ~그땐 JWT에서 받거나 해야하나 고민
        User user = userService.getActiveUser(userId);

        ChatSession chatSession = getChatSessionWithDiaryAndUserById(chatSessionId)
                .orElseThrow(() -> ChatException.chatSessionNotFound(chatSessionId));

        if (!user.equals(chatSession.getDiary().getUser())) {
            throw ChatException.chatSessionUserMismatch(
                    chatSession.getId(),
                    user.getId(),
                    chatSession.getDiary().getUser().getId());
        }

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
