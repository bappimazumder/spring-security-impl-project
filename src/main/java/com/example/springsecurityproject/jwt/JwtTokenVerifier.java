package com.example.springsecurityproject.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


public class JwtTokenVerifier extends OncePerRequestFilter {

    private JwtConfig jwtConfig;

    private SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
       // String secretKey = "SecureSpringKeySecureSpringKeySecureSpringKeySecureSpringKey";
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
                filterChain.doFilter(request,response);
                return;
        }
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(),"");
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);
            Claims body = claimsJws.getBody();
            String userName = body.getSubject();
            List<Map<String, String>> authorities = (List<Map<String, String>>)body.get("authorities");
            Set<GrantedAuthority> grantedAuthorities = authorities.stream().map(a-> new SimpleGrantedAuthority(a.get("authority"))).collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userName,null,grantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (JwtException e){
                throw new IllegalStateException(String.format("This token %s is invalid ",token));
        }
        filterChain.doFilter(request,response);
    }
}
