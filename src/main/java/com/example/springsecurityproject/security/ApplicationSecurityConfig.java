package com.example.springsecurityproject.security;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    protected void configure(HttpSecurity httpSecurity) throws Exception{
       httpSecurity.authorizeRequests()
               .antMatchers("/","index","/css/*","/js/*")
               .permitAll()
               .anyRequest()
               .authenticated()
               .and()
               .httpBasic();
    }
}
