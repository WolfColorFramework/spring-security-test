package com.gaoy.security.formlogin.config;

import com.gaoy.security.formlogin.handler.DefinedLogoutHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private AuthenticationSuccessHandler successHandler;
    @Autowired
    private AuthenticationFailureHandler failureHandler;
    @Autowired
    private DefinedLogoutHandler definedLogoutHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 允许iframe嵌套，解决：frame because it set 'X-Frame-Options' to 'deny 问题
        http.headers().frameOptions().disable();
        // 放行所有option请求
        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .permitAll();

        http.csrf().disable()   // 关闭跨站攻击保护，否则无法进行跨域访问
                .cors()         // 开启跨域支持
                .and().formLogin()
                    .loginPage("/login.html")   // 登录页
                    .loginProcessingUrl("/user/login")   // 登录Action提交url
                    .defaultSuccessUrl("/success.html").permitAll()
                    .failureUrl("/error.html")
//                    .failureHandler(failureHandler)     // 登录失败自定义处理器（会覆盖failureUrl()的设置）
//                    .successHandler(successHandler)     // 登录成功自定义处理器（会覆盖defaultSuccessUrl()的设置）
                .and().logout()   // 退出登录
                    .logoutUrl("/logout")   // 退出Action提交url
                    .addLogoutHandler(definedLogoutHandler) // 退出处理逻辑编写
                .and().exceptionHandling().accessDeniedPage("/unauth.html") // 无权限访问时跳转的html
                // 放开访问权限的url
                .and().authorizeRequests()
                    .antMatchers("/", "/user/login", "/logout", "/user/logout").permitAll()
                    .anyRequest().authenticated();
//                .and().rememberMe()   // 【记住我】功能设置
//                .and().sessionManagement()    // session管理：session有效期、session个数（可实现互踢）

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    // 静态资源全部放行
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .requestMatchers(CorsUtils::isPreFlightRequest) // 放行option请求
                .antMatchers("/static/**");   // 放行配置的静态文件请求
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }

    // 跨域配置
    @Bean
    CorsFilter corsFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin(CorsConfiguration.ALL);
        configuration.addAllowedHeader(CorsConfiguration.ALL);
        configuration.addAllowedMethod(CorsConfiguration.ALL);
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return new CorsFilter(source);
    }
}
