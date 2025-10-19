package me.mmebot.auth.api;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.service.ProviderTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/google")
public class GoogleAuthController {

    private final ProviderTokenService providerTokenService;

    @PostMapping("/token")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void exchangeToken(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state
    ) {
        providerTokenService.storeGoogleAuthorizationCode(code, state);
    }

    @GetMapping("/refresh-token")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void googleCallback(@RequestParam("code") String code,
                               @RequestParam(value = "state", required = false) String state) {
        providerTokenService.refreshAccessToken(code);
    }


}
