package io.jesserDhieb.userService;

import io.jesserDhieb.userService.Entity.Role;
import io.jesserDhieb.userService.Entity.User;
import io.jesserDhieb.userService.Service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null,"jesser dhieb","jesser","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"ameni dhieb","ameni","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"ghaieth dhieb","ghaieth","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"latifa dhieb","latifa","1234",new ArrayList<>()));

			userService.addRoleToUser("jesser","ROLE_USER");
			userService.addRoleToUser("jesser","ROLE_MANAGER");
			userService.addRoleToUser("ameni","ROLE_MANAGER");
			userService.addRoleToUser("ghaieth","ROLE_ADMIN");
			userService.addRoleToUser("latifa","ROLE_USER");
			userService.addRoleToUser("latifa","ROLE_ADMIN");
			userService.addRoleToUser("latifa","ROLE_SUPER_ADMIN");
		};
	}

}
