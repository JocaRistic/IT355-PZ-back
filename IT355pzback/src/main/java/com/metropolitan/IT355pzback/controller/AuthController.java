package com.metropolitan.IT355pzback.controller;

import com.metropolitan.IT355pzback.model.Role;
import com.metropolitan.IT355pzback.model.User;
import com.metropolitan.IT355pzback.model.enums.RoleType;
import com.metropolitan.IT355pzback.payload.request.LoginRequest;
import com.metropolitan.IT355pzback.payload.request.SignupRequest;
import com.metropolitan.IT355pzback.payload.response.MessageResponse;
import com.metropolitan.IT355pzback.repository.RoleRepository;
import com.metropolitan.IT355pzback.repository.UserRepository;
import com.metropolitan.IT355pzback.security.jwt.JwtToken;
import com.metropolitan.IT355pzback.security.jwt.JwtUtils;
import com.metropolitan.IT355pzback.security.services.UserDetails;
import com.metropolitan.IT355pzback.security.services.UserDetailsService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:8081/", maxAge = 3600, allowCredentials = "true")
@AllArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtTokenUtil;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;

    @PostMapping(value = "/login")
    public ResponseEntity<JwtToken> login(@Valid @RequestBody LoginRequest loginRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            final UserDetails userDetails = (UserDetails) userDetailsService.loadUserByUsername(loginRequest.getUsername());

            final String token = jwtTokenUtil.generateToken(userDetails);

            return ResponseEntity.ok(new JwtToken(token));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    @PostMapping(value = "/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) throws Exception {

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(
                signUpRequest.getIme(),
                signUpRequest.getPrezime(),
                signUpRequest.getEmail(),
                signUpRequest.getUsername(),
                encoder.encode(signUpRequest.getPassword())
        );

        Set<String> strRoles = signUpRequest.getRole();
        List<Role> roles = new ArrayList<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(RoleType.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(RoleType.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(RoleType.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

    }

}
