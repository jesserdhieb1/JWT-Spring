package io.jesserDhieb.userService.Repository;

import io.jesserDhieb.userService.Entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role,Long> {
    Role findByName(String name);
}
