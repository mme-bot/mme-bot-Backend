package me.mmebot.diary.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import me.mmebot.diary.api.dto.CreateDiaryRequest;
import me.mmebot.diary.api.dto.DiaryResponse;
import me.mmebot.diary.api.dto.UpdateDiaryRequest;
import me.mmebot.diary.service.DiaryService;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequestMapping("${api.base-path}/diaries")
public class DiaryController {

    private final DiaryService diaryService;

    public DiaryController(DiaryService diaryService) {
        this.diaryService = diaryService;
    }

    @PostMapping
    public DiaryResponse createDiary(@Valid @RequestBody CreateDiaryRequest request) {
        return DiaryResponse.from(diaryService.createDiary(request));
    }

    @GetMapping("/{diaryId}")
    public DiaryResponse getDiary(@PathVariable Long diaryId) {
        return DiaryResponse.from(diaryService.getDiary(diaryId));
    }

    @GetMapping
    public List<DiaryResponse> getDiaries(@RequestParam("userId") @NotNull Long userId) {
        return diaryService.getDiariesByUser(userId).stream()
                .map(DiaryResponse::from)
                .toList();
    }

    @PutMapping("/{diaryId}")
    public DiaryResponse updateDiary(@PathVariable Long diaryId,
                                     @Valid @RequestBody UpdateDiaryRequest request) {
        return DiaryResponse.from(diaryService.updateDiary(diaryId, request));
    }

    @DeleteMapping("/{diaryId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteDiary(@PathVariable Long diaryId) {
        diaryService.deleteDiary(diaryId);
    }
}
