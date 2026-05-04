package me.mmebot.diary.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;
import me.mmebot.diary.domain.DiaryEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DiaryResponseMapperTest {

    @Mock
    private AesGcmCryptoService aesGcmCryptoService;

    @InjectMocks
    private DiaryResponseMapper diaryResponseMapper;

    @Test
    void toDetailDecryptsContentAndMapsDiaryFields() {
        byte[] aadHash = "aad-hash".getBytes();
        String encryptedContent = "encrypted-content";
        String decryptedContent = "decrypted-content";
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

        when(aesGcmCryptoService.decryptWithAad(encryptedContent, aadHash))
                .thenReturn(decryptedContent);

        DiaryDetail detail = diaryResponseMapper.toDetail(diary);

        assertThat(detail.diaryId()).isEqualTo(1L);
        assertThat(detail.content()).isEqualTo(decryptedContent);
        assertThat(detail.emotion()).isEqualTo("happy");
        assertThat(detail.date()).isEqualTo(diaryDate);
        assertThat(detail.createdAt()).isEqualTo(createdAt);
        assertThat(detail.updatedAt()).isEqualTo(updatedAt);
        verify(aesGcmCryptoService).decryptWithAad(encryptedContent, aadHash);
    }
}
