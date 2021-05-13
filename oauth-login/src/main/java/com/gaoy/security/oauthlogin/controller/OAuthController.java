package com.gaoy.security.oauthlogin.controller;

import com.gaoy.security.oauthlogin.domain.SecurityUser;
import com.gaoy.security.oauthlogin.domain.Social;
import com.gaoy.security.oauthlogin.domain.User;
import com.gaoy.security.oauthlogin.handler.MyUserDetailsService;
import com.gaoy.security.oauthlogin.utils.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
public class OAuthController {

    @Autowired
    TokenManager tokenManager;

    @Autowired
    MyUserDetailsService myUserDetailsService;

    // 应该存在redis中
    public static Map<String, Social> socials = new HashMap<>();

    private static final String KEY = "YOU APP_ID";
    private static final String SECRET = "YOU SECURITY";

    @GetMapping("/token")
    public String token(@RequestParam String code) {

        // 获取access_token
        String url = "https://api.weibo.com/oauth2/access_token";
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url)
                // Add query parameter
                .queryParam("client_id", KEY)
                .queryParam("client_secret", SECRET)
                .queryParam("grant_type", "authorization_code")
                .queryParam("redirect_uri", "http://192.168.0.14:9730/oauth/token")
                .queryParam("code", code);

        RestTemplate restTemplate = new RestTemplateBuilder().build();
        Social social = restTemplate.postForObject(builder.toUriString(), null, Social.class);
        socials.put(social.getUid(), social);

        // 生成token
        User user = new User("admin", "123", "社交登录id");
        SecurityUser securityUser = new SecurityUser(user, social, null);
        String token = tokenManager.generateToken(securityUser);
        return token;
    }
}
