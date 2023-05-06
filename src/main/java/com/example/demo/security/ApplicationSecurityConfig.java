package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JWTUsernamePasswordAuthenticationFilter;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.*;

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    public PasswordEncoder passwordEncoder;
    public ApplicationUserService applicationUserService;
//    private final SecretKey secretKey;
//    private final JwtConfig jwtConfig =new JwtConfig();

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
     http
       .csrf().disable()//this we did bcz put/post method giving us 403 forbidden
             .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //as jwt token are stateless we will add this line to tell the system to not store the token
             .and()
             .addFilter(new JWTUsernamePasswordAuthenticationFilter(authenticationManager()))
             .addFilterAfter(new JwtTokenVerifier(),JWTUsernamePasswordAuthenticationFilter.class)
        .authorizeRequests()
             .antMatchers("/","index","/css/*","/js/*","/login").permitAll()
             .antMatchers("/api/**").hasRole(STUDENT.name())
             .anyRequest()
             .authenticated();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(applicationUserService);
        return  daoAuthenticationProvider;
    }

}
