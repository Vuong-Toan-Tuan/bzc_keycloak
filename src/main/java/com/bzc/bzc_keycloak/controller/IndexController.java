package com.bzc.bzc_keycloak.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
public class IndexController {

//    @GetMapping(path = "/")
//    public HashMap index() {
//        OAuth2User user = ((OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
//        return new HashMap(){{
//            put("hello", user.getAttribute("name"));
//            put("your email is", user.getAttribute("email"));
//        }};
//    }
//
//    @GetMapping(path = "/unauthenticated")
//    public HashMap unauthenticatedRequests() {
//        return new HashMap(){{
//            put("this is ", "unauthenticated endpoint");
//        }};
//    }
}