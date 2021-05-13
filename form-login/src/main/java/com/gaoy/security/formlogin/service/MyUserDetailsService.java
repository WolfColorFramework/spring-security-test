package com.gaoy.security.formlogin.service;

import com.gaoy.security.formlogin.domain.SecurityUser;
import com.gaoy.security.formlogin.domain.User;
import com.sun.org.apache.xerces.internal.dom.PSVIAttrNSImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 根据username 获取到用户信息
        // userRepository.getUserByUsername(username);
        User user = new User("admin", "123");

        // 根据User获取对应的权限
        // menuRepository.getMenusByUsername(username);
        List<String> menus = new ArrayList<>();

        List<GrantedAuthority> auths =
                AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", menus));
        return new SecurityUser(user.getUsername(),
                new BCryptPasswordEncoder().encode(user.getPassword()), auths);
    }
}
