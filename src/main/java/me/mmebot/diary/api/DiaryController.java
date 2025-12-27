package me.mmebot.diary.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.service.DiaryService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static me.mmebot.diary.api.dto.DiaryResponse.*;
import static me.mmebot.diary.api.dto.DiaryResponse.DiaryDetail;

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

//    @GetMapping("/{diaryId}")
//    public DiaryDetail getDiary(@PathVariable Long diaryId) {
//        return diaryService.getDiary(diaryId);
//    }

//    @GetMapping
//    public List<DiaryResponse> getDiaries(@RequestParam("userId") @NotNull Long userId) {
//        return diaryService.getDiariesByUser(userId).stream()
//                .map(DiaryResponse::from)
//                .toList();
//    }
//
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
