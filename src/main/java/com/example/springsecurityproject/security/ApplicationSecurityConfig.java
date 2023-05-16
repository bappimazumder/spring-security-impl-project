package com.example.springsecurityproject.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.springsecurityproject.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecurityproject.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
               /*.antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(), ADMINTRANEE.name())*/
               .anyRequest()
               .authenticated()
               .and()
               .formLogin()
                     .loginPage("/login").permitAll()
                     .defaultSuccessUrl("/courses",true)
                     .usernameParameter("username")
                     .passwordParameter("password")
               .and()
               .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("keysecured")
                    .rememberMeParameter("remember-me")
               .and()
               .logout()
                   .logoutUrl("/logout")
                   .clearAuthentication(true)
                   .invalidateHttpSession(true)
                   .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                   .deleteCookies("JSESSIONID","remember-me")
                   .logoutSuccessUrl("/login");

    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
      UserDetails userBappi =  User.builder()
                .username("bappimazumder")
                .password(passwordEncoder.encode("HelloSecurity1"))
              //  .roles(STUDENT.name())
              .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails userAkash =  User.builder()
                .username("akash")
                .password(passwordEncoder.encode("HelloSecurity2"))
                //.roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails userTrainee =  User.builder()
                .username("adam")
                .password(passwordEncoder.encode("HelloSecurity3"))
                //.roles(ADMINTRANEE.name())
                .authorities(ADMINTRANEE.getGrantedAuthorities())
                .build();
       return new InMemoryUserDetailsManager(userBappi,userAkash,userTrainee);
    }
}
