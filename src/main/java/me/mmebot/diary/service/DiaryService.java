package me.mmebot.diary.service;

import static me.mmebot.diary.api.dto.DiaryResponse.*;

import java.time.LocalDate;
import java.time.YearMonth;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.mmebot.common.crypto.AesGcmCryptoService;
import me.mmebot.user.service.UserService;
import me.mmebot.core.service.EncryptionContextFactory;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.domain.DiaryEntity;
import me.mmebot.diary.exception.DiaryException;
import me.mmebot.diary.mapper.DiaryResponseMapper;
import me.mmebot.diary.repository.DiaryRepository;
import me.mmebot.user.domain.UserEntity;
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
    private final DiaryResponseMapper diaryResponseMapper;

    public CreateDiaryRes createDiary(CreateDiaryRequest request) {
        UserEntity user = userService.getActiveUser(request.userId());
        ensureUniqueDiaryDate(user.getId(), request.date());

//        String summaryShort = openAiService.diarySummarizeShort(request.content());

        String aadStr = user.getId().toString();
//        String summaryShortEnc = aesGcmCryptoService.encryptWithAad(summaryShort, aadStr);
        String contentEnc = aesGcmCryptoService.encryptWithAad(request.content(), aadStr);

        DiaryEntity diary = DiaryEntity.builder()
                .user(user)
                .content(contentEnc)
                .emotion(request.emotion())
//                .summaryShort(summaryShortEnc)
                .date(request.date())
                .encryptionContext(encryptionContextFactory.createContext(aadStr))
                .build();

        DiaryEntity saved = saveDiary(diary);
        return new CreateDiaryRes(diary.getId());
    }

    @Transactional
    protected DiaryEntity saveDiary(DiaryEntity diary) {
        return diaryRepository.save(diary);
    }

    @Transactional(readOnly = true)
    public DiaryListItem getDiary(Long diaryId) {
        return diaryResponseMapper.toListItem(getActiveDiary(diaryId));
    }

    @Transactional(readOnly = true)
    public List<DiaryListItem> getDiariesByUserAndMonth(Long userId, Integer year, Integer month) {
        UserEntity user = userService.getActiveUser(userId);
        YearMonth yearMonth = YearMonth.of(year, month);
        LocalDate startDate = yearMonth.atDay(1);
        LocalDate endDate = yearMonth.atEndOfMonth();
        List<DiaryListItem> details = diaryRepository
                .findMonthlyDiaries(user.getId(), startDate, endDate)
                .stream()
                .map(diaryResponseMapper::toListItem)
                .toList();
        return details;
    }

//    public DiaryListItem updateDiary(Long diaryId, UpdateDiaryRequest request) {
//        log.info("Updating diary {} for date {}", diaryId, request.date());
//        DiaryEntity diary = getActiveDiary(diaryId);
//        ensureUniqueDiaryDate(diary.getUser().getId(), request.date(), diaryId);
//
//        String summaryShort = openAiService.diarySummarizeShort(request.content());
//        diary.update(request.content().strip(), request.emotion(), summaryShort, request.date());
//        log.info("DiaryEntity {} updated", diaryId);
//        return diaryResponseMapper.toListItem(diary);
//    }
//
//    public void deleteDiary(Long diaryId) {
//        log.info("Deleting diary {}", diaryId);
//        DiaryEntity diary = getActiveDiary(diaryId);
//        diary.markDeleted(OffsetDateTime.now());
//        log.info("DiaryEntity {} marked as deleted", diaryId);
//    }

    public DiaryEntity getActiveDiary(Long diaryId) {
        return diaryRepository.findByIdAndDeletedAtIsNull(diaryId)
                .orElseThrow(() -> {
                    log.warn("DiaryEntity {} not found or deleted", diaryId);
                    return DiaryException.diaryNotFound(diaryId);
                });
    }

    private void ensureUniqueDiaryDate(Long userId, LocalDate date) {
        diaryRepository.findByUserIdAndDateAndDeletedAtIsNull(userId, date)
                .ifPresent(existing -> {
                    log.warn("DiaryEntity {} already exists for user {} on {}", existing.getId(), userId, date);
                    throw DiaryException.diaryAlreadyExists(date);
                });
    }
}
