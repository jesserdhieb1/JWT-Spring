package io.jesserDhieb.userService.Service;

import io.jesserDhieb.userService.Entity.Role;
import io.jesserDhieb.userService.Entity.User;
import io.jesserDhieb.userService.Repository.RoleRepo;
import io.jesserDhieb.userService.Repository.UserRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
@Service
public class UserServiceImp implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImp(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override// on utilise cette methode pour que spring security utilise et connait nos Users
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user==null){
            log.error("User not found in DB");
            throw new UsernameNotFoundException("User not found in DB");
        }else{
            log.error("User found in DB {}",username);
        }
        Collection<SimpleGrantedAuthority> athorities=new ArrayList<>();
        user.getRoles().forEach(role -> {
            athorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),athorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("saving User {} to a data base",user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving Role {} to a data base",role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding  Role {} to User {} ",roleName,username);
        User user =userRepo.findByUsername(username);
        Role role =roleRepo.findByName(roleName);
        user.getRoles().add(role);
        userRepo.save(user);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}",username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all Users");
        return userRepo.findAll();
    }


}
