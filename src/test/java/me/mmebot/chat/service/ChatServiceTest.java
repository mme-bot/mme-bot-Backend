package me.mmebot.chat.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.mmebot.bot.domain.Bot;
import me.mmebot.chat.api.dto.ChatMsgReq.CreateChatMsgReq;
import me.mmebot.chat.api.dto.ChatMsgReq.StartChatReq;
import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.api.dto.ChatMsgRes.ChatStreamPayload;
import me.mmebot.chat.api.dto.ChatMsgRes.CreateChatMsgRes;
import me.mmebot.chat.api.dto.ChatMsgRes.StartChatRes;
import me.mmebot.chat.api.dto.ChatMsgRes.StreamStatus;
import me.mmebot.chat.api.dto.ChatSessionReq.CreateChatSessionReq;
import me.mmebot.chat.api.dto.ChatSessionRes.CreateChatSessionRes;
import me.mmebot.chat.domain.ChatMessage;
import me.mmebot.chat.domain.ChatSession;
import me.mmebot.chat.domain.ChatSessionStatus;
import me.mmebot.chat.exception.ChatException;
import me.mmebot.chat.repository.ChatMessageRepository;
import me.mmebot.chat.repository.ChatSessionRepository;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.core.domain.EncryptionContext;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.core.service.TemplateService;
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.service.DiaryService;
import me.mmebot.openai.dto.ChatMessageRole;
import me.mmebot.openai.dto.ChatStreamResponse;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.stream.StreamContextStore;
import me.mmebot.stream.StreamContextContent.ChatStreamContext;
import me.mmebot.stream.StreamContextContent.FirstChatStreamContext;
import me.mmebot.user.domain.User;
import me.mmebot.user.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import reactor.core.publisher.Flux;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChatServiceTest {

    @Mock
    private ChatMessageRepository chatMessageRepository;
    @Mock
    private ChatSessionRepository chatSessionRepository;
    @Mock
    private DiaryService diaryService;
    @Mock
    private UserService userService;
    @Mock
    private OpenAIService openAIService;
    @Mock
    private AesGcmCryptoService aesGcmCryptoService;
    @Mock
    private EncryptionContextFactory encryptionContextFactory;
    @Mock
    private StreamContextStore streamContextStore;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private TemplateService templateService;
    @InjectMocks
    private ChatService chatService;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(templateService.generatePrompt(anyString(), anyMap())).thenReturn("prompt");
        lenient().when(objectMapper.writeValueAsString(any())).thenAnswer(invocation -> {
            Object arg = invocation.getArgument(0);
            if (arg instanceof ChatStreamResponse response) {
                return response.content();
            }
            return "{}";
        });
    }

    @Test
    void 오늘_일기로_채팅세션을_생성() {
        Long userId = 21L;
        Long diaryId = 31L;
        User user = buildUser(userId);
        Diary diary = buildDiary(diaryId, user, LocalDate.now(), "short-summary-enc");
        EncryptionContext context = encryptionContext("ctx", 1);

        when(diaryService.getActiveDiary(diaryId)).thenReturn(diary);
        when(chatSessionRepository.findByDiaryId(diaryId)).thenReturn(Optional.empty());
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(context);
        // session 객체를 save 할 경우, id = 77 객체를 돌려주도록 함.
        doAnswer(invocation -> {
            ChatSession session = invocation.getArgument(0);
            ReflectionTestUtils.setField(session, "id", 77L);
            return session;
        }).when(chatSessionRepository).save(any(ChatSession.class));

        CreateChatSessionRes res = chatService.createChatSession(new CreateChatSessionReq(userId, diaryId));

        assertThat(res.chatSessionId()).isEqualTo(77L);
        verify(chatSessionRepository).save(any(ChatSession.class));
    }

    @Test
    void 동일_일기세션이_이미_존재하면_생성을_차단() {
        Long userId = 99L;
        Long diaryId = 551L;
        User user = buildUser(userId);
        Diary diary = buildDiary(diaryId, user, LocalDate.now(), "enc");
        ChatSession existing = ChatSession.builder()
                .id(88L)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("existing", 3))
                .build();

        when(diaryService.getActiveDiary(diaryId)).thenReturn(diary);
        when(chatSessionRepository.findByDiaryId(diaryId)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> chatService.createChatSession(new CreateChatSessionReq(userId, diaryId)))
                .isInstanceOf(ChatException.class);
    }

    @Test
    void 채팅메시지_작성시_암호화하여_사용자와_봇메시지를_저장() {
        Long userId = 12L;
        Long chatSessionId = 44L;
        Long replyMsgId = 101L;
        String streamId = "stream-1";
        User user = buildUser(userId);
        Diary diary = buildDiary(78L, user, LocalDate.now(), "summary-enc");
        ChatSession chatSession = ChatSession.builder()
                .id(chatSessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 5))
                .build();
        EncryptionContext replyEncCtx = encryptionContext("reply", 7);
        ChatMessage replyMsg = ChatMessage.builder()
                .id(replyMsgId)
                .chatSession(chatSession)
                .seq(1)
                .role(ChatMessageRole.ASSISTANT)
                .content("reply-content")
                .encryptionContext(replyEncCtx)
                .createdAt(OffsetDateTime.now())
                .build();
        EncryptionContext userEnc = encryptionContext("aad-user", 9);
        ChatStreamContext streamContext = new ChatStreamContext(
                chatSessionId,
                userId,
                replyMsgId,
                "message",
                LocalDateTime.now()
        );

        when(streamContextStore.get(streamId)).thenReturn(streamContext);
        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(chatSessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of());
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession))
                .thenReturn(new java.util.ArrayList<>(List.of(replyMsg)));
        when(openAIService.sendChatMessage(eq("prompt"), anyList(), eq("message")))
                .thenReturn(Flux.just(new ChatStreamResponse(1L, "테스트")));
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(userEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("message"), any(byte[].class))).thenReturn("enc-user");
        when(aesGcmCryptoService.encryptWithAad(eq("테스트"), any(byte[].class))).thenReturn("enc-ai");
        lenient().when(aesGcmCryptoService.decryptWithAad(eq("enc-user"), any(byte[].class))).thenReturn("message");
        lenient().when(aesGcmCryptoService.decryptWithAad(eq("enc-ai"), any(byte[].class))).thenReturn("테스트");
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage msg = invocation.getArgument(0);
            ReflectionTestUtils.setField(msg, "id", 300L + msg.getSeq());
            return msg;
        });

        List<ChatStreamPayload> responses = chatService.createChatMessage(streamId)
                .collectList()
                .block();

        assertThat(responses).hasSize(3);
        assertThat(responses.get(0).status()).isEqualTo(StreamStatus.LOADING);
        assertThat(responses.get(1).status()).isEqualTo(StreamStatus.STREAMING);
        assertThat(responses.get(1).content()).isEqualTo("테스트");
        assertThat(responses.get(2).status()).isEqualTo(StreamStatus.DONE);
        assertThat(responses.get(2).msgId()).isEqualTo(303L);

        verify(chatMessageRepository, times(2)).save(any(ChatMessage.class));
        verify(streamContextStore).remove(streamId);
    }

    @Test
    void 동일_답장메시지가_이미_존재하면_예외() {
        Long userId = 1L;
        Long sessionId = 2L;
        Long replyMsgId = 10L;
        String streamId = "stream-dup";
        User user = buildUser(userId);
        Diary diary = buildDiary(3L, user, LocalDate.now(), "enc");
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 3))
                .build();
        ChatMessage replyMsg = ChatMessage.builder()
                .id(replyMsgId)
                .chatSession(chatSession)
                .seq(3)
                .role(ChatMessageRole.ASSISTANT)
                .content("reply")
                .encryptionContext(encryptionContext("reply", 4))
                .createdAt(OffsetDateTime.now())
                .build();
        ChatStreamContext streamContext = new ChatStreamContext(
                sessionId,
                userId,
                replyMsgId,
                "hello",
                LocalDateTime.now()
        );

        when(streamContextStore.get(streamId)).thenReturn(streamContext);
        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of(replyMsg));

        assertThatThrownBy(() -> chatService.createChatMessage(streamId))
                .isInstanceOf(ChatException.class);
    }

    @Test
    void 사용자_메시지가_20개_이상이면_예외() {
        Long userId = 1L;
        Long sessionId = 2L;
        Long replyMsgId = 10L;
        String streamId = "stream-limit";
        User user = buildUser(userId);
        Diary diary = buildDiary(3L, user, LocalDate.now(), "enc");
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 3))
                .build();
        ChatMessage replyMsg = ChatMessage.builder()
                .id(replyMsgId)
                .chatSession(chatSession)
                .seq(1)
                .role(ChatMessageRole.ASSISTANT)
                .content("reply")
                .encryptionContext(encryptionContext("reply", 4))
                .createdAt(OffsetDateTime.now())
                .build();
        List<ChatMessage> chatMessages = new java.util.ArrayList<>();
        chatMessages.add(replyMsg);
        for (int i = 0; i < 21; i++) {
            chatMessages.add(buildChatMessage(chatSession, i + 2, ChatMessageRole.USER));
        }
        ChatStreamContext streamContext = new ChatStreamContext(
                sessionId,
                userId,
                replyMsgId,
                "hello",
                LocalDateTime.now()
        );

        when(streamContextStore.get(streamId)).thenReturn(streamContext);
        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of());
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(chatMessages);

        assertThatThrownBy(() -> chatService.createChatMessage(streamId))
                .isInstanceOf(ChatException.class);
    }

    @Test
    void 첫_채팅시_오픈ai_응답으로_세션을_초기화() {
        Long userId = 5L;
        Long sessionId = 9L;
        String streamId = "stream-first";
        User user = buildUser(userId);
        EncryptionContext diaryEnc = encryptionContext("diary", 15);
        Diary diary = buildDiary(777L, user, LocalDate.now(), "short-enc");
        ReflectionTestUtils.setField(diary, "encryptionContext", diaryEnc);
        ReflectionTestUtils.setField(diary, "content", "short-enc");
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 8))
                .build();
        EncryptionContext msgEnc = encryptionContext("msg", 20);
        FirstChatStreamContext streamContext = new FirstChatStreamContext(
                sessionId,
                userId,
                LocalDateTime.now()
        );

        when(streamContextStore.get(streamId)).thenReturn(streamContext);
        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(List.of());
        when(aesGcmCryptoService.decryptWithAad("short-enc", diaryEnc.getAadHash())).thenReturn("plain");
        when(openAIService.sendFirstChatMsg("prompt"))
                .thenReturn(Flux.just(new ChatStreamResponse(1L, "first-msg")));
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(msgEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("first-msg"), any(byte[].class))).thenReturn("first-msg-enc");
        lenient().when(aesGcmCryptoService.decryptWithAad(eq("first-msg-enc"), any(byte[].class))).thenReturn("first-msg");
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage message = invocation.getArgument(0);
            ReflectionTestUtils.setField(message, "id", 100L + message.getSeq());
            return message;
        });

        List<ChatStreamPayload> responses = chatService.createFirstChat(streamId)
                .collectList()
                .block();

        assertThat(responses).hasSize(3);
        assertThat(responses.get(0).status()).isEqualTo(StreamStatus.LOADING);
        assertThat(responses.get(1).status()).isEqualTo(StreamStatus.STREAMING);
        assertThat(responses.get(1).content()).isEqualTo("first-msg");
        assertThat(responses.get(2).status()).isEqualTo(StreamStatus.DONE);
        assertThat(responses.get(2).msgId()).isEqualTo(101L);

        verify(chatMessageRepository).save(any(ChatMessage.class));
        verify(streamContextStore).remove(streamId);
    }

    @Test
    void 단일_응답으로_첫_채팅을_생성() {
        Long userId = 7L;
        Long sessionId = 15L;
        User user = buildUser(userId);
        Diary diary = buildDiary(900L, user, LocalDate.now(), "short" );
        ReflectionTestUtils.setField(diary, "content", "enc-content");
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 13))
                .build();
        EncryptionContext diaryEnc = diary.getEncryptionContext();
        EncryptionContext msgEnc = encryptionContext("first", 40);

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(List.of());
        when(aesGcmCryptoService.decryptWithAad("enc-content", diaryEnc.getAadHash())).thenReturn("plain");
        when(openAIService.sendFirstChatMsgSync("prompt")).thenReturn("assistant");
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(msgEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("assistant"), any(byte[].class))).thenReturn("assistant-enc");
        when(aesGcmCryptoService.decryptWithAad("assistant-enc", msgEnc.getAadHash())).thenReturn("assistant");
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage message = invocation.getArgument(0);
            ReflectionTestUtils.setField(message, "id", 400L + message.getSeq());
            return message;
        });

        StartChatRes res = chatService.createFirstChatSync(sessionId, new StartChatReq(userId));

        assertThat(res.chatMsgId()).isEqualTo(401L);
        assertThat(res.msg()).isEqualTo("assistant");
        verify(chatMessageRepository).save(any(ChatMessage.class));
    }

    @Test
    void 채팅_메시지_목록을_정렬된_복호화결과로_반환() {
        Long sessionId = 888L;
        User user = buildUser(321L);
        Diary diary = buildDiary(55L, user, LocalDate.now(), "enc");
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 22))
                .build();
        EncryptionContext msgEnc1 = encryptionContext("m1", 30);
        EncryptionContext msgEnc2 = encryptionContext("m2", 31);
        ChatMessage second = ChatMessage.builder()
                .id(2L)
                .chatSession(chatSession)
                .seq(2)
                .role(ChatMessageRole.USER)
                .content("enc-2")
                .encryptionContext(msgEnc2)
                .createdAt(OffsetDateTime.now())
                .build();
        ChatMessage first = ChatMessage.builder()
                .id(1L)
                .chatSession(chatSession)
                .seq(1)
                .role(ChatMessageRole.ASSISTANT)
                .content("enc-1")
                .encryptionContext(msgEnc1)
                .createdAt(OffsetDateTime.now())
                .build();

        when(userService.getActiveUser(user.getId())).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(List.of(second, first));
        when(aesGcmCryptoService.decryptWithAad("enc-1", msgEnc1.getAadHash())).thenReturn("first");
        when(aesGcmCryptoService.decryptWithAad("enc-2", msgEnc2.getAadHash())).thenReturn("second");

        List<ChatMsg> chatMsgs = chatService.getChatMsgs(user.getId(), sessionId);

        assertThat(chatMsgs).hasSize(2);
        assertThat(chatMsgs.getFirst().seq()).isEqualTo(1);
        assertThat(chatMsgs.getFirst().msg()).isEqualTo("first");
        assertThat(chatMsgs.get(1).seq()).isEqualTo(2);
        assertThat(chatMsgs.get(1).msg()).isEqualTo("second");
    }

    @Test
    void 단일_응답으로_채팅_메시지를_저장() {
        Long userId = 11L;
        Long chatSessionId = 41L;
        Long replyMsgId = 300L;
        User user = buildUser(userId);
        Diary diary = buildDiary(901L, user, LocalDate.now(), "sum");
        ChatSession chatSession = ChatSession.builder()
                .id(chatSessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 90))
                .build();
        ChatMessage replyMsg = ChatMessage.builder()
                .id(replyMsgId)
                .chatSession(chatSession)
                .seq(1)
                .role(ChatMessageRole.ASSISTANT)
                .content("reply")
                .encryptionContext(encryptionContext("reply", 91))
                .createdAt(OffsetDateTime.now())
                .build();
        EncryptionContext userEnc = encryptionContext("user", 92);

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(chatSessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of());
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession))
                .thenReturn(new java.util.ArrayList<>(List.of(replyMsg)));
        when(openAIService.sendChatMessageSync(eq("prompt"), anyList(), eq("message")))
                .thenReturn("assistant");
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(userEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("message"), any(byte[].class))).thenReturn("message-enc");
        when(aesGcmCryptoService.encryptWithAad(eq("assistant"), any(byte[].class))).thenReturn("assistant-enc");
        when(aesGcmCryptoService.decryptWithAad("message-enc", userEnc.getAadHash())).thenReturn("message");
        when(aesGcmCryptoService.decryptWithAad("assistant-enc", userEnc.getAadHash())).thenReturn("assistant");
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage message = invocation.getArgument(0);
            ReflectionTestUtils.setField(message, "id", 500L + message.getSeq());
            return message;
        });

        List<CreateChatMsgRes> result = chatService.createChatMessageSync(
                chatSessionId,
                new CreateChatMsgReq(userId, replyMsgId, "message")
        );

        assertThat(result).hasSize(2);
        assertThat(result.get(0).role()).isEqualTo(ChatMessageRole.USER);
        assertThat(result.get(0).msg()).isEqualTo("message");
        assertThat(result.get(1).role()).isEqualTo(ChatMessageRole.ASSISTANT);
        assertThat(result.get(1).msg()).isEqualTo("assistant");
        verify(chatMessageRepository, times(2)).save(any(ChatMessage.class));
    }

    private User buildUser(Long id) {
        Bot bot = Bot.builder()
                .id(5L)
                .name("몽몽")
                .persona("persona")
                .script("script")
                .build();
        return User.builder()
                .id(id)
                .bot(bot)
                .nickname("nickname" + id)
                .sns(false)
                .build();
    }

    private Diary buildDiary(Long id, User user, LocalDate date, String summaryShort) {
        return Diary.builder()
                .id(id)
                .user(user)
                .content("content")
                .emotion("JOY")
                .summaryShort(summaryShort)
                .date(date)
                .encryptionContext(encryptionContext("diary" + id, id.intValue()))
                .build();
    }

    private ChatMessage buildChatMessage(ChatSession chatSession, int seq, ChatMessageRole role) {
        return ChatMessage.builder()
                .id((long) seq)
                .chatSession(chatSession)
                .seq(seq)
                .role(role)
                .content("enc-" + seq)
                .encryptionContext(encryptionContext("msg" + seq, seq))
                .createdAt(OffsetDateTime.now())
                .build();
    }

    private EncryptionContext encryptionContext(String seed, int salt) {
        byte[] aad = (seed + salt).getBytes(StandardCharsets.UTF_8);
        return EncryptionContext.builder()
                .id((long) salt)
                .iv(new byte[]{1, 2, 3})
                .tag(new byte[]{4, 5, 6})
                .aadHash(aad)
                .key(null)
                .build();
    }
}
