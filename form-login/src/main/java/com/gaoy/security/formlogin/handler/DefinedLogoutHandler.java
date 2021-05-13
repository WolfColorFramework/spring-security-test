package com.gaoy.security.formlogin.handler;

import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class DefinedLogoutHandler implements LogoutHandler {
    @SneakyThrows
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // 处理一些退出的逻辑
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("退出登录");
    }
}
