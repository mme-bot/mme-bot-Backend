package me.mmebot.diary.mapper;

import lombok.RequiredArgsConstructor;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryListItem;
import me.mmebot.diary.domain.DiaryEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DiaryResponseMapper {

    private final AesGcmCryptoService aesGcmCryptoService;

    public DiaryListItem toListItem(DiaryEntity diary) {
        return new DiaryListItem(
                diary.getId(),
                diary.getEmotion(),
                diary.getDate()
        );
    }

    public DiaryDetail toDetail(DiaryEntity diary) {
        byte[] aadHash = diary.getEncryptionContext().getAadHash();

        return new DiaryDetail(
                diary.getId(),
                aesGcmCryptoService.decryptWithAad(diary.getContent(), aadHash),
                diary.getEmotion(),
                diary.getDate(),
                diary.getCreatedAt(),
                diary.getUpdatedAt()
        );
    }
}
