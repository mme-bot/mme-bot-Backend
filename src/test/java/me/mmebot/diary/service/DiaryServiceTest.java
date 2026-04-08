package me.mmebot.diary.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Optional;
import me.mmebot.bot.domain.BotEntity;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.api.dto.DiaryResponse.CreateDiaryRes;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;
import me.mmebot.diary.domain.DiaryEntity;
import me.mmebot.diary.exception.DiaryException;
import me.mmebot.diary.repository.DiaryRepository;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.user.domain.UserEntity;
import me.mmebot.user.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class DiaryServiceTest {

    @Mock
    private AesGcmCryptoService aesGcmCryptoService;
    @Mock
    private DiaryRepository diaryRepository;
    @Mock
    private UserService userService;
    @Mock
    private EncryptionContextFactory encryptionContextFactory;
    @Mock
    private OpenAIService openAiService;

    @InjectMocks
    private DiaryService diaryService;

    @Test
    void 일기_생성시_암호화후_저장() {
        Long userId = 10L;
        LocalDate date = LocalDate.of(2024, 8, 21);
        CreateDiaryRequest request = new CreateDiaryRequest(userId, "today-content", "JOY", date);
        UserEntity user = buildUser(userId);
        EncryptionContextEntity encryptionContext = encryptionContext("diary", 3);

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(diaryRepository.findByUserIdAndDateAndDeletedAtIsNull(userId, date)).thenReturn(Optional.empty());
        when(aesGcmCryptoService.encryptWithAad("today-content", userId.toString())).thenReturn("content-enc");
        when(encryptionContextFactory.createContext(userId.toString())).thenReturn(encryptionContext);
        when(diaryRepository.save(any(DiaryEntity.class))).thenAnswer(invocation -> {
            DiaryEntity diary = invocation.getArgument(0);
            ReflectionTestUtils.setField(diary, "id", 55L);
            return diary;
        });

        CreateDiaryRes res = diaryService.createDiary(request);

        assertThat(res.diaryId()).isEqualTo(55L);
        ArgumentCaptor<DiaryEntity> diaryCaptor = ArgumentCaptor.forClass(DiaryEntity.class);
        verify(diaryRepository).save(diaryCaptor.capture());
        DiaryEntity saved = diaryCaptor.getValue();
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getContent()).isEqualTo("content-enc");
        assertThat(saved.getSummaryShort()).isNull();
        assertThat(saved.getDate()).isEqualTo(date);
        assertThat(saved.getEmotion()).isEqualTo("JOY");
        assertThat(saved.getEncryptionContext()).isEqualTo(encryptionContext);
    }

    @Test
    void 같은_날짜에_일기가_존재하면_예외() {
        Long userId = 50L;
        LocalDate date = LocalDate.of(2024, 3, 11);
        CreateDiaryRequest request = new CreateDiaryRequest(userId, "content", "SAD", date);
        UserEntity user = buildUser(userId);
        DiaryEntity existing = DiaryEntity.builder()
                .id(77L)
                .user(user)
                .content("enc")
                .emotion("SAD")
                .summaryShort("sum")
                .date(date)
                .encryptionContext(encryptionContext("exist", 5))
                .build();

        when(userService.getActiveUser(userId)).thenReturn(user);
        when(diaryRepository.findByUserIdAndDateAndDeletedAtIsNull(userId, date)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> diaryService.createDiary(request)).isInstanceOf(DiaryException.class);
        verify(diaryRepository, never()).save(any(DiaryEntity.class));
    }

    @Test
    void 일기를_조회하면_복호화된_상세정보를_반환() {
        Long diaryId = 91L;
        UserEntity user = buildUser(7L);
        EncryptionContextEntity context = encryptionContext("ctx", 9);
        OffsetDateTime createdAt = OffsetDateTime.now().minusDays(1);
        OffsetDateTime updatedAt = OffsetDateTime.now();
        DiaryEntity diary = DiaryEntity.builder()
                .id(diaryId)
                .user(user)
                .content("cipher")
                .emotion("LOVE")
                .summaryShort("short")
                .date(LocalDate.of(2024, 5, 3))
                .createdAt(createdAt)
                .updatedAt(updatedAt)
                .encryptionContext(context)
                .build();

        when(diaryRepository.findByIdAndDeletedAtIsNull(diaryId)).thenReturn(Optional.of(diary));
        when(aesGcmCryptoService.decryptWithAad("cipher", context.getAadHash())).thenReturn("plain");

        DiaryDetail detail = diaryService.getDiary(diaryId);

        assertThat(detail.diaryId()).isEqualTo(diaryId);
        assertThat(detail.content()).isEqualTo("plain");
        assertThat(detail.emotion()).isEqualTo("LOVE");
        assertThat(detail.date()).isEqualTo(diary.getDate());
        assertThat(detail.createdAt()).isEqualTo(createdAt);
        assertThat(detail.updatedAt()).isEqualTo(updatedAt);
    }

    @Test
    void 삭제되었거나_없으면_활성_일기_조회시_예외가_발생() {
        Long diaryId = 808L;
        when(diaryRepository.findByIdAndDeletedAtIsNull(diaryId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> diaryService.getActiveDiary(diaryId)).isInstanceOf(DiaryException.class);
    }

    private UserEntity buildUser(Long id) {
        BotEntity bot = BotEntity.builder()
                .id(1L)
                .name("mme-bot")
                .persona("persona")
                .script("script")
                .build();
        return UserEntity.builder()
                .id(id)
                .bot(bot)
                .nickname("nickname" + id)
                .sns(false)
                .build();
    }

    private EncryptionContextEntity encryptionContext(String seed, int salt) {
        byte[] aad = (seed + salt).getBytes(StandardCharsets.UTF_8);
        return EncryptionContextEntity.builder()
                .id((long) salt)
                .iv(new byte[]{1, 2, 3})
                .tag(new byte[]{4, 5, 6})
                .aadHash(aad)
                .key(null)
                .build();
    }
}
