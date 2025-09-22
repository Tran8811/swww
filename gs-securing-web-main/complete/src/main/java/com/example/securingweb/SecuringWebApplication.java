package com.example.securingweb;

import com.example.securingweb.model.User;
import com.example.securingweb.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecuringWebApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuringWebApplication.class, args);
	}

	@Bean
	public CommandLineRunner demo(UserRepository repository, PasswordEncoder passwordEncoder) {
		return (args) -> {
			// Xóa dữ liệu cũ
			repository.deleteAll();

			// User USER (password hashed)
			User user = new User("user", passwordEncoder.encode("password"), "USER");
			repository.save(user);

			// User ADMIN (password hashed)
			User admin = new User("admin", passwordEncoder.encode("admin"), "ADMIN");
			repository.save(admin);

			System.out.println("Users saved to MySQL: USER (user/password), ADMIN (admin/admin)");
		};
	}
}