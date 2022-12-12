package com.example.config;

import com.example.payload.User;
import com.example.repository.UserRepository;
import com.example.util.HttpServletRequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();
        final String ip = HttpServletRequestUtil.getIP();

        if (ObjectUtils.isEmpty(username) || ObjectUtils.isEmpty(password)) {
            throw new BadCredentialsException("Credenciales incorrectas, por favor intente nuevamente.");
        }

        User userObj = userRepository.findByUsername(username);

        if (isAuthValid(userObj, authentication)) {
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    userObj,
                    password,
                    Collections.emptyList()
            );
            token.setDetails(authentication.getDetails());
            return token;
        } else {
            throw new BadCredentialsException("Credenciales incorrectas, por favor intente nuevamente.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private boolean isAuthValid(User user, Authentication authentication) {
        if (user == null) return false;
        String username = user.username;
        String password = user.password;
        String authUsername = authentication.getName();
        String authPassword = authentication.getCredentials().toString();
        if (username == null || password == null || authUsername == null || authPassword == null) {
            return false;
        }
        return password.equals(authPassword);
    }

}
