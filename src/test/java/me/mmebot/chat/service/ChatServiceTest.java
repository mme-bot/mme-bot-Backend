package me.mmebot.chat.service;

import me.mmebot.bot.domain.Bot;
import me.mmebot.chat.api.dto.ChatMsgReq.CreateChatMsgReq;
import me.mmebot.chat.api.dto.ChatMsgReq.StartChatReq;
import me.mmebot.chat.api.dto.ChatMsgRes.ChatMsg;
import me.mmebot.chat.api.dto.ChatMsgRes.CreateChatMsgRes;
import me.mmebot.chat.api.dto.ChatMsgRes.StartChatRes;
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
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.service.DiaryService;
import me.mmebot.openai.dto.ChatMessageRole;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.user.domain.User;
import me.mmebot.user.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    @InjectMocks
    private ChatService chatService;

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
                .role(ChatMessageRole.SYSTEM)
                .content("reply-content")
                .encryptionContext(replyEncCtx)
                .createdAt(OffsetDateTime.now())
                .build();
        EncryptionContext userEnc = encryptionContext("aad-user", 9);

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(chatSessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of());
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(new java.util.ArrayList<>(List.of(replyMsg)));
        when(aesGcmCryptoService.decryptWithAad("summary-enc", userId.toString())).thenReturn("summary");
        when(openAIService.sendChatMessage(eq("summary"), anyList(), eq("message"))).thenReturn("테스트");
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(userEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("message"), same(userEnc.getAadHash()))).thenReturn("enc-user");
        when(aesGcmCryptoService.encryptWithAad(eq("테스트"), same(userEnc.getAadHash()))).thenReturn("enc-ai");

        AtomicLong idSeq = new AtomicLong(300);
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage msg = invocation.getArgument(0);
            ReflectionTestUtils.setField(msg, "id", idSeq.incrementAndGet());
            return msg;
        });

        List<CreateChatMsgRes> result = chatService.createChatMessage(chatSessionId, new CreateChatMsgReq(userId, replyMsgId, "message"));

        assertThat(result).hasSize(2);
        assertThat(result.getFirst().chatMsgId()).isEqualTo(301L);
        assertThat(result.getFirst().seq()).isEqualTo(2);
        assertThat(result.getFirst().msg()).isEqualTo("message");
        assertThat(result.get(1).chatMsgId()).isEqualTo(302L);
        assertThat(result.get(1).msg()).isEqualTo("테스트");
        verify(chatMessageRepository, times(2)).save(any(ChatMessage.class));
    }

    @Test
    void 동일_답장메시지가_이미_존재하면_예외() {
        Long userId = 1L;
        Long sessionId = 2L;
        Long replyMsgId = 10L;
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
                .role(ChatMessageRole.SYSTEM)
                .content("reply")
                .encryptionContext(encryptionContext("reply", 4))
                .createdAt(OffsetDateTime.now())
                .build();

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findById(replyMsgId)).thenReturn(Optional.of(replyMsg));
        when(chatMessageRepository.findAllByReplyMsgId(replyMsgId)).thenReturn(List.of(replyMsg));

        assertThatThrownBy(() -> chatService.createChatMessage(sessionId, new CreateChatMsgReq(userId, replyMsgId, "hello")))
                .isInstanceOf(ChatException.class);
    }

    @Test
    void 첫_채팅시_오픈ai_응답으로_세션을_초기화() {
        Long userId = 5L;
        Long sessionId = 9L;
        User user = buildUser(userId);
        EncryptionContext diaryEnc = encryptionContext("diary", 15);
        Diary diary = buildDiary(777L, user, LocalDate.now(), "short-enc");
        ReflectionTestUtils.setField(diary, "encryptionContext", diaryEnc);
        ChatSession chatSession = ChatSession.builder()
                .id(sessionId)
                .diary(diary)
                .bot(user.getBot())
                .status(ChatSessionStatus.ACTIVE)
                .sendCount(0)
                .encryptionContext(encryptionContext("session", 8))
                .build();
        EncryptionContext msgEnc = encryptionContext("msg", 20);

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(List.of());
        when(aesGcmCryptoService.decryptWithAad("short-enc", diaryEnc.getAadHash())).thenReturn("plain");
        when(openAIService.sendFirstChatMsg("plain")).thenReturn("first-msg");
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(msgEnc);
        when(aesGcmCryptoService.encryptWithAad(eq("resMsg"), same(msgEnc.getAadHash()))).thenReturn("first-msg-enc");
        when(chatMessageRepository.save(any(ChatMessage.class))).thenAnswer(invocation -> {
            ChatMessage message = invocation.getArgument(0);
            ReflectionTestUtils.setField(message, "id", 901L);
            return message;
        });

        StartChatRes res = chatService.createFirstChat(sessionId, new StartChatReq(userId));

        assertThat(res.chatMsgId()).isEqualTo(901L);
        assertThat(res.msg()).isEqualTo("first-msg");
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
                .role(ChatMessageRole.SYSTEM)
                .content("enc-1")
                .encryptionContext(msgEnc1)
                .createdAt(OffsetDateTime.now())
                .build();

        when(chatSessionRepository.findWithDiaryAndUser(sessionId)).thenReturn(Optional.of(chatSession));
        when(chatMessageRepository.findAllByChatSessionWithEnc(chatSession)).thenReturn(List.of(second, first));
        when(aesGcmCryptoService.decryptWithAad("enc-1", msgEnc1.getAadHash())).thenReturn("first");
        when(aesGcmCryptoService.decryptWithAad("enc-2", msgEnc2.getAadHash())).thenReturn("second");

        List<ChatMsg> chatMsgs = chatService.getChatMsgs(sessionId);

        assertThat(chatMsgs).hasSize(2);
        assertThat(chatMsgs.getFirst().seq()).isEqualTo(1);
        assertThat(chatMsgs.getFirst().msg()).isEqualTo("first");
        assertThat(chatMsgs.get(1).seq()).isEqualTo(2);
        assertThat(chatMsgs.get(1).msg()).isEqualTo("second");
    }

    private User buildUser(Long id) {
        Bot bot = Bot.builder()
                .id(5L)
                .name("mme-bot")
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
