package com.gaoy.security.jwtlogin.config;

import com.gaoy.security.jwtlogin.filter.TokenAuthFilter;
import com.gaoy.security.jwtlogin.filter.TokenLoginFilter;
import com.gaoy.security.jwtlogin.handler.TokenLogoutHandler;
import com.gaoy.security.jwtlogin.handler.UnAuthEntryPoint;
import com.gaoy.security.jwtlogin.utils.TokenManager;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenManager tokenManager;
    private UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, TokenManager tokenManager) {
        this.userDetailsService = userDetailsService;
        this.tokenManager = tokenManager;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 允许iframe嵌套，解决：frame because it set 'X-Frame-Options' to 'deny 问题
        http.headers().frameOptions().disable();

        // 放开所有前置请求
        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .permitAll();

        http.csrf().disable()   // 关闭跨站攻击保护，否则无法跨域访问
                .exceptionHandling()
                .authenticationEntryPoint(new UnAuthEntryPoint())   // 认证失败处理器
            .and().cors()   // 开放跨域访问
            .and().httpBasic()
                .and().authorizeRequests()
                .antMatchers("/login").permitAll() // 可直接访问的url
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/logout")
                .addLogoutHandler(new TokenLogoutHandler(tokenManager))
                .and().addFilter(new TokenLoginFilter(authenticationManager(), tokenManager))
                .addFilter(new TokenAuthFilter(authenticationManager(), tokenManager, userDetailsService));
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }

    // 静态资源路径
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/static/**");
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
