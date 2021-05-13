package com.gaoy.security.oauthlogin.utils;

import com.gaoy.security.oauthlogin.domain.SecurityUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenManager {
    // 编码秘钥
    private String secret = "abcd";

    /**
     * 生成token
     *
     * @param securityUser 用户信息
     * @return
     */
    public String generateToken(SecurityUser securityUser) {
        Map<String, Object> claims = new HashMap<>(2);
        claims.put("sub", securityUser.getUsername());
        claims.put("created", new Date());
        return generateToken(claims, securityUser.getSocial().getExpires_in() * 1000);
    }

    /**
     * 生成token
     *
     * @param claims 用户数据
     * @return
     */
    private String generateToken(Map<String, Object> claims, Long expiration) {
        Date expirationDate = new Date(System.currentTimeMillis() + expiration);
        return Jwts.builder().setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    /**
     * 从令牌中获取用户名
     *
     * @param token 令牌
     * @return 用户名
     */
    public String getUsernameFromToken(String token) {
        String username;
        try {
            Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * 从令牌中获取数据声明
     *
     * @param token 令牌
     * @return 数据声明
     */
    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    public void removeToken(String token) {
    }

    /**
     * 验证令牌
     *
     * @param token        令牌
     * @param securityUser 用户
     * @return 是否有效
     */
    public Boolean validateToken(String token, SecurityUser securityUser) {

        String username = getUsernameFromToken(token);
        return (username.equals(securityUser.getUsername()) && !isTokenExpired(token));
    }

    /**
     * 判断令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public Boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
