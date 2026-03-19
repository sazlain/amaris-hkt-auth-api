package com.amaris.hkt.auth.api.service.impl;

import com.amaris.hkt.auth.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * FIX: Extracted from SecurityConfig to break the circular dependency chain.
 * SecurityConfig -> AuthenticationProvider -> UserDetailsService (was @Bean inside SecurityConfig)
 * -> UserRepository. Now it's a standalone @Service injected directly.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Usuario no encontrado con username: " + username));
    }
}
