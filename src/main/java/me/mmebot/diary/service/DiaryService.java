package me.mmebot.diary.service;

import static me.mmebot.diary.api.dto.DiaryResponse.*;

import java.time.LocalDate;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.user.service.UserService;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.domain.Diary;
import me.mmebot.diary.exception.DiaryException;
import me.mmebot.diary.repository.DiaryRepository;
import me.mmebot.openai.service.OpenAIService;
import me.mmebot.user.domain.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class DiaryService {

    private final AesGcmCryptoService aesGcmCryptoService;
    private final DiaryRepository diaryRepository;
    private final UserService userService;
    private final EncryptionContextFactory encryptionContextFactory;
    private final OpenAIService openAiService;

    public CreateDiaryRes createDiary(CreateDiaryRequest request) {
        log.info("Creating diary for user {} on {}", request.userId(), request.date());
        User user = userService.getActiveUser(request.userId());
        ensureUniqueDiaryDate(user.getId(), request.date());

        String summaryShort = openAiService.diarySummarizeShort(request.content());

        String aadStr = user.getId().toString();
        String summaryShortEnc = aesGcmCryptoService.encryptWithAad(summaryShort, aadStr);
        String contentEnc = aesGcmCryptoService.encryptWithAad(request.content(), aadStr);

        Diary diary = Diary.builder()
                .user(user)
                .content(contentEnc)
                .emotion(request.emotion())
                .summaryShort(summaryShortEnc)
                .date(request.date())
                .encryptionContext(encryptionContextFactory.createContext(aadStr))
                .build();

        Diary saved = saveDiary(diary);
        log.info("Diary {} created for user {} on {}", saved.getId(), saved.getUser().getId(), saved.getDate());
        return new CreateDiaryRes(diary.getId());
    }

    @Transactional
    protected Diary saveDiary(Diary diary) {
        return diaryRepository.save(diary);
    }

    @Transactional(readOnly = true)
    public DiaryDetail getDiary(Long diaryId) {
        log.debug("Fetching diary {}", diaryId);
        return toDetail(getActiveDiary(diaryId));
    }

//    @Transactional(readOnly = true)
//    public List<DiaryDetail> getDiariesByUser(Long userId) {
//        log.debug("Fetching diaries for user {}", userId);
//        User user = userService.getActiveUser(userId);
//        List<DiaryDetail> details = diaryRepository.findByUserIdAndDeletedAtIsNullOrderByDateDesc(user.getId()).stream()
//                .map(DiaryService::toDetail)
//                .toList();
//        log.debug("Fetched {} diaries for user {}", details.size(), userId);
//        return details;
//    }
//
//    public DiaryDetail updateDiary(Long diaryId, UpdateDiaryRequest request) {
//        log.info("Updating diary {} for date {}", diaryId, request.date());
//        Diary diary = getActiveDiary(diaryId);
//        ensureUniqueDiaryDate(diary.getUser().getId(), request.date(), diaryId);
//
//        String summaryShort = openAiService.diarySummarizeShort(request.content());
//        diary.update(request.content().strip(), request.emotion(), summaryShort, request.date());
//        log.info("Diary {} updated", diaryId);
//        return toDetail(diary);
//    }
//
//    public void deleteDiary(Long diaryId) {
//        log.info("Deleting diary {}", diaryId);
//        Diary diary = getActiveDiary(diaryId);
//        diary.markDeleted(OffsetDateTime.now());
//        log.info("Diary {} marked as deleted", diaryId);
//    }

    public Diary getActiveDiary(Long diaryId) {
        return diaryRepository.findByIdAndDeletedAtIsNull(diaryId)
                .orElseThrow(() -> {
                    log.warn("Diary {} not found or deleted", diaryId);
                    return DiaryException.diaryNotFound(diaryId);
                });
    }

    private void ensureUniqueDiaryDate(Long userId, LocalDate date) {
        diaryRepository.findByUserIdAndDateAndDeletedAtIsNull(userId, date)
                .ifPresent(existing -> {
                    log.warn("Diary {} already exists for user {} on {}", existing.getId(), userId, date);
                    throw DiaryException.diaryAlreadyExists(date);
                });
    }

    private DiaryDetail toDetail(Diary diary) {
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
