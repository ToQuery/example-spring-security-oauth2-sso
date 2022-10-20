package io.github.toquery.example.spring.security.oauth2.sso;

import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@Import(AppProperties.class)
@SpringBootApplication
public class ExampleSpringSecurityOauth2SsoApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExampleSpringSecurityOauth2SsoApplication.class, args);
	}

}
