package io.jesserDhieb.userService.Repository;

import io.jesserDhieb.userService.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User,Long> {
    User findByUsername(String username);
}
