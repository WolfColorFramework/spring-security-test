package com.gaoy.security.oauthlogin.handler;

import com.gaoy.security.oauthlogin.controller.OAuthController;
import com.gaoy.security.oauthlogin.domain.SecurityUser;
import com.gaoy.security.oauthlogin.domain.Social;
import com.gaoy.security.oauthlogin.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component("userDetailsService")
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 根据uid 获取到用户信息
        // userRepository.getUserByUsername(username);
        User user = new User("admin", "123", "社交登录id");
        // 根据uid，获取到social
        // socialRepository.getSocialByUid(String uid);
        Social social = OAuthController.socials.get("2467687434");

        // 没有对应的数据 or 时间过期
        if (user == null || social == null || social.getExpiresDate().before(new Date())) {
            if (social != null)
                OAuthController.socials.remove(social.getUid());
            throw new UsernameNotFoundException("用户不存在 or 已失效");
        }

        // 根据User获取对应的权限
        // menuRepository.getMenusByUsername(username);
        List<String> menus = new ArrayList<>();

        List<GrantedAuthority> auths =
                AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", menus));
        //从查询数据库返回users对象，得到用户名和密码，返回
        return new SecurityUser(user, social, auths);
    }
}
