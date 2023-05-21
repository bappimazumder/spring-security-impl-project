package com.example.springsecurityproject.security;
import com.example.springsecurityproject.auth.ApplicationUserService;
import com.example.springsecurityproject.jwt.JwtConfig;
import com.example.springsecurityproject.jwt.JwtTokenVerifier;
import com.example.springsecurityproject.jwt.JwtUsernameAndPasswordAuthenticationFilter;
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

import static com.example.springsecurityproject.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;

    private final SecretKey secretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService, JwtConfig jwtConfig, SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    protected void configure(HttpSecurity httpSecurity) throws Exception{
       httpSecurity
               .csrf().disable()
               .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and()
               .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
               .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
               .authorizeRequests()
               .antMatchers("/","index","/css/*","/js/*").permitAll()
               .antMatchers("/api/**").hasRole(STUDENT.name())
               /*.antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
               .antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(), ADMINTRANEE.name())*/
               .anyRequest()
               .authenticated()
               /*.and()
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
                   .logoutSuccessUrl("/login")*/
       ;

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

   /* @Override
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
    }*/
}
