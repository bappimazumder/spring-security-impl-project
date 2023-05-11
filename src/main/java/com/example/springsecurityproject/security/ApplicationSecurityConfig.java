package com.example.springsecurityproject.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    protected void configure(HttpSecurity httpSecurity) throws Exception{
       httpSecurity.authorizeRequests()
               .antMatchers("/","index","/css/*","/js/*")
               .permitAll()
               .anyRequest()
               .authenticated()
               .and()
               .httpBasic();
    }

    @Override
    protected UserDetailsService userDetailsService() {
      UserDetails userBappi =  User.builder()
                .username("bappimazumder")
                .password(passwordEncoder.encode("HelloSecurity"))
                .roles("STUDENT")
                .build();
       return new InMemoryUserDetailsManager(userBappi);
    }
}
