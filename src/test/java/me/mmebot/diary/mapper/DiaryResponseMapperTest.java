package me.mmebot.diary.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Base64;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.common.crypto.AesGcmUtils;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryListItem;
import me.mmebot.diary.domain.DiaryEntity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DiaryResponseMapper 테스트")
class DiaryResponseMapperTest {

    private final AesGcmCryptoService aesGcmCryptoService =
            new AesGcmCryptoService(Base64.getEncoder().encodeToString(AesGcmUtils.generateRandomKey()));

    private final DiaryResponseMapper diaryResponseMapper = new DiaryResponseMapper(aesGcmCryptoService);

    @Test
    @DisplayName("Diary 도메인을 일기 목록 응답으로 변환한다")
    void toListItemMapsDiaryFields() {
        byte[] aadHash = "aad-hash".getBytes();
        String encryptedContent = "encrypted-content";
        LocalDate diaryDate = LocalDate.of(2026, 5, 4);

        EncryptionContextEntity encryptionContext = EncryptionContextEntity.builder()
                .aadHash(aadHash)
                .build();
        DiaryEntity diary = DiaryEntity.builder()
                .id(1L)
                .content(encryptedContent)
                .emotion("happy")
                .date(diaryDate)
                .encryptionContext(encryptionContext)
                .build();

        DiaryListItem detail = diaryResponseMapper.toListItem(diary);

        assertThat(detail.diaryId()).isEqualTo(1L);
        assertThat(detail.emotion()).isEqualTo("happy");
        assertThat(detail.date()).isEqualTo(diaryDate);
    }

    @Test
    @DisplayName("Diary 도메인의 암호화된 본문을 복호화해 일기 상세 응답으로 변환한다")
    void toDetailDecryptsContentAndMapsDiaryFields() {
        byte[] aadHash = "aad-hash".getBytes();
        String decryptedContent = "decrypted-content";
        String encryptedContent = aesGcmCryptoService.encryptWithAad(decryptedContent, aadHash);
        LocalDate diaryDate = LocalDate.of(2026, 5, 4);
        OffsetDateTime createdAt = OffsetDateTime.parse("2026-05-04T10:15:30+09:00");
        OffsetDateTime updatedAt = OffsetDateTime.parse("2026-05-04T11:20:30+09:00");

        EncryptionContextEntity encryptionContext = EncryptionContextEntity.builder()
                .aadHash(aadHash)
                .build();
        DiaryEntity diary = DiaryEntity.builder()
                .id(1L)
                .content(encryptedContent)
                .emotion("happy")
                .date(diaryDate)
                .createdAt(createdAt)
                .updatedAt(updatedAt)
                .encryptionContext(encryptionContext)
                .build();

        DiaryDetail detail = diaryResponseMapper.toDetail(diary);

        assertThat(detail.diaryId()).isEqualTo(1L);
        assertThat(detail.content()).isEqualTo(decryptedContent);
        assertThat(detail.emotion()).isEqualTo("happy");
        assertThat(detail.date()).isEqualTo(diaryDate);
        assertThat(detail.createdAt()).isEqualTo(createdAt);
        assertThat(detail.updatedAt()).isEqualTo(updatedAt);
    }
}
