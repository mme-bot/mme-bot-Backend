package me.mmebot.diary.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;

import me.mmebot.core.domain.EncryptionContextEntity;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryListItem;
import me.mmebot.diary.domain.DiaryEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DiaryResponseMapperTest {

    @InjectMocks
    private DiaryResponseMapper diaryResponseMapper;

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
}
