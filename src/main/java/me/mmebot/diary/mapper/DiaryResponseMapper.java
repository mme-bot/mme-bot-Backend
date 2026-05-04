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
        return new DiaryDetail(
                diary.getId(),
                diary.getEmotion(),
                diary.getDate()
        );
    }
}
