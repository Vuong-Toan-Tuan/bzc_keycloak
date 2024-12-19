package com.bzc.bzc_keycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
@RequestMapping("/api")
public class UserController {

//    private final OAuth2AuthorizedClientService authorizedClientService;
//
//    public UserController(OAuth2AuthorizedClientService authorizedClientService) {
//        this.authorizedClientService = authorizedClientService;
//    }
//
//    @GetMapping("/token")
//    public Map<String, String> getToken(@AuthenticationPrincipal OAuth2User principal, OAuth2AuthenticationToken authentication) {
//        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
//                authentication.getAuthorizedClientRegistrationId(),
//                authentication.getName()
//        );
//
//        String accessToken = authorizedClient.getAccessToken().getTokenValue();
//        String refreshToken = authorizedClient.getRefreshToken() != null
//                ? authorizedClient.getRefreshToken().getTokenValue()
//                : null;
//
//        Map<String, String> tokens = new HashMap<>();
//        tokens.put("access_token", accessToken);
//        tokens.put("refresh_token", refreshToken);
//        tokens.put("user", principal.getName());
//
//        return tokens;
//    }

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Public endpoint - accessible by anyone!";
    }

    @GetMapping("/protected")
    public String protectedEndpoint() {
        return "Protected endpoint - accessible only to authenticated users!";
    }



    @GetMapping("/accessBZC")
    @PreAuthorize("hasRole('bzc_user')")
    public String Endpoint0() {
        return "Tài khoản này có quyền sử dụng hệ thống BZC!";
    }

    @GetMapping("/accessBZW")
    @PreAuthorize("hasRole('bzw_user')")
    public String Endpoint1() {
        return "Tài khoản này có quyền sử dụng hệ thống BZW!";
    }

    @GetMapping("/accessBZT")
    @PreAuthorize("hasRole('bzt_user')")
    public String Endpoint2() {
        return "Tài khoản này có quyền sử dụng hệ thống BZT!";
    }

    @GetMapping("/accessTMS")
    @PreAuthorize("hasRole('tms_user')")
    public String Endpoint3() {
        return "Tài khoản này có quyền sử dụng hệ thống TMS!";
    }
}
