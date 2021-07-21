package com.example.demo.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static com.example.demo.security.SecurityConstants.SIGN_UP_URL;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserDetailsServiceImplementation userDetailsServiceImplementation;

    public WebSecurityConfig(BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailsServiceImplementation userDetailsServiceImplementation) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userDetailsServiceImplementation = userDetailsServiceImplementation;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAuthFilter(authenticationManager()))
                .addFilter(new JWTAuthVerFilter(authenticationManager()))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.parentAuthenticationManager(authenticationManagerBean())
                .userDetailsService(userDetailsServiceImplementation)
                .passwordEncoder(bCryptPasswordEncoder);

    }
}