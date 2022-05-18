package com.programmers.devcourse.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .defaultSuccessUrl("/me")
                .permitAll()
                .and()
                /**
                 * rememberMe 설정
                 */
                .rememberMe()
                .tokenValiditySeconds(300)
                .and()
                /**
                 * 로그아웃 설정
                 */
                .logout()
                .logoutSuccessUrl("/")
                .and()
                /**
                 * HTTP -> HTTPS 요청으로 리다이렉트
                 */
                .requiresChannel()
                .anyRequest().requiresSecure()
                .and()
                /**
                 * anonymous 설정
                 */
                .anonymous()
                .principal("thisIsAnonymousUser")
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                .and()
                /**
                 * 커스텀 에러 핸들링
                 */
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER").and()
                .withUser("admin").password("{noop}admin123").roles("ADMIN");
    }
}
