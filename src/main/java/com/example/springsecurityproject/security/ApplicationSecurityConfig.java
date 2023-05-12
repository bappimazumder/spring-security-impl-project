package com.example.springsecurityproject.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springsecurityproject.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    protected void configure(HttpSecurity httpSecurity) throws Exception{
       httpSecurity
               .csrf().disable()
               .authorizeRequests()
               .antMatchers("/","index","/css/*","/js/*").permitAll()
               .antMatchers("/api/**").hasRole(STUDENT.name())
               .anyRequest()
               .authenticated()
               .and()
               .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
      UserDetails userBappi =  User.builder()
                .username("bappimazumder")
                .password(passwordEncoder.encode("HelloSecurity"))
                .roles(STUDENT.name())
                .build();

        UserDetails userAkash =  User.builder()
                .username("akash")
                .password(passwordEncoder.encode("HelloSecurity"))
                .roles(ADMIN.name())
                .build();

        UserDetails userTrainee =  User.builder()
                .username("adam")
                .password(passwordEncoder.encode("HelloSecurity"))
                .roles(ADMINTRANEE.name())
                .build();
       return new InMemoryUserDetailsManager(userBappi,userAkash,userTrainee);
    }
}
