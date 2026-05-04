package me.mmebot.diary.mapper;

import lombok.RequiredArgsConstructor;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;
import me.mmebot.diary.domain.DiaryEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DiaryResponseMapper {

    private final AesGcmCryptoService aesGcmCryptoService;

    public DiaryDetail toDetail(DiaryEntity diary) {
        byte[] aadHash = diary.getEncryptionContext().getAadHash();
        String content = aesGcmCryptoService.decryptWithAad(diary.getContent(), aadHash);

        return new DiaryDetail(
                diary.getId(),
                content,
                diary.getEmotion(),
                diary.getDate(),
                diary.getCreatedAt(),
                diary.getUpdatedAt()
        );
    }
}
