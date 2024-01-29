package io.github.toquery.example.spring.security.oauth2.jwt;

import io.github.toquery.example.spring.security.oauth2.jwt.core.properties.AppJwtProperties;
import io.github.toquery.example.spring.security.oauth2.jwt.core.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({AppProperties.class, AppJwtProperties.class})
@SpringBootApplication
public class ExampleSpringSecurityOauth2JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExampleSpringSecurityOauth2JwtApplication.class, args);
	}

}
