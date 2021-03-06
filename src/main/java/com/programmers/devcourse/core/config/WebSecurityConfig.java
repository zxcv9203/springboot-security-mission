package com.programmers.devcourse.core.config;

import com.programmers.devcourse.application.user.service.UserService;
import com.programmers.devcourse.core.jwt.Jwt;
import com.programmers.devcourse.core.jwt.JwtAuthenticationFilter;
import com.programmers.devcourse.core.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.programmers.devcourse.core.oauth2.OAuth2AuthenticationSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final JwtConfigure jwtConfigure;

    public WebSecurityConfig(JwtConfigure jwtConfigure) {
        this.jwtConfigure = jwtConfigure;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
                jwtConfigure.getIssuer(),
                jwtConfigure.getClientSecret(),
                jwtConfigure.getExpirySeconds()
        );
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        Jwt jwt = getApplicationContext().getBean(Jwt.class);
        return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcOperations jdbcOperations,
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(Jwt jwt, UserService userService) {
        return new OAuth2AuthenticationSuccessHandler(jwt, userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/user/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
                /**
                 * formLogin, csrf, headers, http-basic, rememberMe, logout filter ????????????
                 */
                .formLogin()
                .disable()
                .csrf()
                .disable()
                .headers()
                .disable()
                .httpBasic()
                .disable()
                .rememberMe()
                .disable()
                .logout()
                .disable()
                /**
                 * Session ???????????? ??????
                 */
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                /**
                 * OAuth2 ??????
                 */
                .oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestRepository(authorizationRequestRepository())
                .and()
                .successHandler(getApplicationContext().getBean(OAuth2AuthenticationSuccessHandler.class))
                .authorizedClientRepository(getApplicationContext().getBean(AuthenticatedPrincipalOAuth2AuthorizedClientRepository.class))
                .and()
                /**
                 * ???????????? ?????????
                 */
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                /**
                 * Jwt ??????
                 */
                .addFilterAfter(jwtAuthenticationFilter(), SecurityContextPersistenceFilter.class)
        ;
    }

}
