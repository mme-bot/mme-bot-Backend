package me.mmebot.auth.api;

import lombok.RequiredArgsConstructor;
import me.mmebot.auth.service.ProviderTokenService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${api.base-path}/google")
public class GoogleAuthController {

    private final ProviderTokenService providerTokenService;

    @GetMapping("/token")
    public void exchangeToken(@RequestParam("code") String code) {
        providerTokenService.storeGoogleAuthorizationCode(code);
    }

    @PostMapping("/refresh-token")
    public void googleCallback() {
        providerTokenService.refreshAccessToken();
    }


}
