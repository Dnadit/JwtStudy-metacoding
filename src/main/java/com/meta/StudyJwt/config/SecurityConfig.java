package com.meta.StudyJwt.config;

import com.meta.StudyJwt.config.jwt.JwtAuthenticationFilter;
import com.meta.StudyJwt.config.jwt.JwtAuthorizationFilter;
import com.meta.StudyJwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable() // restapi는 loginform이 필요없음
                .httpBasic().disable() // httpBasic은 id와 pw를 들고 가는거라서 노출되면 위험함
                .apply(new MyCustomDs1())
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('USER') or hasRole('MANAGER') or hasRole('ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('MANAGER') or hasRole('ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ADMIN')")
                .anyRequest().permitAll()
                .and()
                .build();
    }

    public class MyCustomDs1 extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
