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
import org.junit.jupiter.api.Test;

class DiaryResponseMapperTest {

    private final AesGcmCryptoService aesGcmCryptoService =
            new AesGcmCryptoService(Base64.getEncoder().encodeToString(AesGcmUtils.generateRandomKey()));

    private final DiaryResponseMapper diaryResponseMapper = new DiaryResponseMapper(aesGcmCryptoService);

    @Test
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
