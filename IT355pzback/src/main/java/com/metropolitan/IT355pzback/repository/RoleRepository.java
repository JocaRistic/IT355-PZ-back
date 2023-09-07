package com.metropolitan.IT355pzback.repository;

import com.metropolitan.IT355pzback.model.Role;
import com.metropolitan.IT355pzback.model.enums.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(RoleType name);

}
