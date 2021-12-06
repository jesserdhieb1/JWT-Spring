package io.jesserDhieb.userService.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){//if the path is /api/login let it pass to the next filter which is the api
            filterChain.doFilter(request,response);
        }else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);//getting the auth header from the request
            if (authorizationHeader!=null&&authorizationHeader.startsWith("Bearer ")){
               try {
                   String token = authorizationHeader.substring("Bearer ".length());//removing the Bearer from the head an then adding it to the token
                   Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());//algorithm which the token was generated
                   JWTVerifier verifier= JWT.require(algorithm).build();
                   DecodedJWT decodedJWT =verifier.verify(token);//verify the token with the verifier
                   String username= decodedJWT.getSubject();//getting the username
                   String[] roles= decodedJWT.getClaim("roles").asArray(String.class);//getting the roles in an array of string
                   Collection<SimpleGrantedAuthority> authorities =new ArrayList<>();
                   stream(roles).forEach(role->{
                       authorities.add(new SimpleGrantedAuthority(role));//changing the types of role from String to SimpleGrantedAuthority
                   });
                   UsernamePasswordAuthenticationToken authenticationToken=
                           new UsernamePasswordAuthenticationToken(username,null,authorities);
                   SecurityContextHolder.getContext().setAuthentication(authenticationToken);//telling Spring Security the username and the roles of the User requestion an api
                   filterChain.doFilter(request,response);// pass to next filter (api)
               }

               catch (Exception exception){
                   log.info("Error logging in : {}",exception.getMessage());
                   response.setHeader("error",exception.getMessage());
                   response.setStatus(FORBIDDEN.value());
                   //response.sendError(FORBIDDEN.value());
                   Map<String,String> error =new HashMap<>();
                   error.put("error_message",exception.getMessage());
                   response.setContentType(APPLICATION_JSON_VALUE);
                   new ObjectMapper().writeValue(response.getOutputStream(),error);
               }

            }else {
                filterChain.doFilter(request,response);//else pass to the next filter
            }

        }
    }
}
