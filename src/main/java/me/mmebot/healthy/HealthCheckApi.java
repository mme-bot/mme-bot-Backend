package me.mmebot.healthy;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/healthy")
public class HealthCheckApi {

    @GetMapping
    public ResponseEntity<String> healthy() {
        return ResponseEntity.ok("OK");
    }

}
