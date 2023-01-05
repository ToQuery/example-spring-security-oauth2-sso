package io.github.toquery.example.spring.security.oauth2.sso;

import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppJwtProperties;
import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

@EnableConfigurationProperties({AppProperties.class, AppJwtProperties.class})
@SpringBootApplication
public class ExampleSpringSecurityOauth2SsoJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExampleSpringSecurityOauth2SsoJwtApplication.class, args);
	}

}
