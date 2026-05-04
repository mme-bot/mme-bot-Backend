package me.mmebot.diary.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.api.dto.GetDiariesRequest;
import me.mmebot.diary.service.DiaryService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static me.mmebot.diary.api.dto.DiaryResponse.*;
import static me.mmebot.diary.api.dto.DiaryResponse.DiaryListItem;

@RestController
@Validated
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/diaries")
public class DiaryController {

    private final DiaryService diaryService;

    @PostMapping
    public CreateDiaryRes createDiary(@Valid @RequestBody CreateDiaryRequest request) {
        return diaryService.createDiary(request);
    }

    @GetMapping("/{diaryId}")
    public DiaryDetail getDiary(@PathVariable Long diaryId) {
        return diaryService.getDiary(diaryId);
    }

    @GetMapping
    public List<DiaryListItem> getDiaries(
            @AuthenticationPrincipal Long userId,
            @Valid @ModelAttribute GetDiariesRequest request
    ) {
        return diaryService.getDiariesByUserAndMonth(userId, request.year(), request.month());
    }

//    @PutMapping("/{diaryId}")
//    public DiaryResponse updateDiary(@PathVariable Long diaryId,
//                                     @Valid @RequestBody UpdateDiaryRequest request) {
//        return DiaryResponse.from(diaryService.updateDiary(diaryId, request));
//    }
//
//    @DeleteMapping("/{diaryId}")
//    @ResponseStatus(HttpStatus.NO_CONTENT)
//    public void deleteDiary(@PathVariable Long diaryId) {
//        diaryService.deleteDiary(diaryId);
//    }
}
