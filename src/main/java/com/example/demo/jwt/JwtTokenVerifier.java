package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

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



    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        String key = "securesfhslfjlifykjshfkjshfkhfsecuresfhslfjlifykjshfkjshfkhfsecuresfhslfjlifykjshfkjshfkhfsecuresfhslfjlifykjshfkjshfkhfsecuresfhslfjlifykjshfkjshfkhfsecuresfhslfjlifykjshfkjshfkhf";


        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.contains("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String token = authorizationHeader.replace("Bearer ","");
        try{
            //get the user and authorities related information from the token
        Jws<Claims> claimsJws = Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
                .parseClaimsJws(token);
        // claim object contain the username we set the token expiry time and the creation time
        Claims body = claimsJws.getBody();
        String username = body.getSubject();
        //this authorities are set in the claim object in the form of List of map key as  "authorities" and value as value
        var authorities = (List<Map<String, String>>) body.get("authorities");
        Set<SimpleGrantedAuthority> simpleGrantedAuthorityList = authorities.stream().map(auth -> new SimpleGrantedAuthority(auth.get("authority"))).collect(Collectors.toSet());

        // as its a validate token we need to create the
            // authentication  object again with the username and authorities and need to pass it to security context holder
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                username,
                null,
                simpleGrantedAuthorityList
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        }catch (Exception e){
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }
        filterChain.doFilter(request, response);

    }
}
