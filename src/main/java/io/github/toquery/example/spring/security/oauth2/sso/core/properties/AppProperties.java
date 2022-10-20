package io.github.toquery.example.spring.security.oauth2.sso.core.properties;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;

import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@Slf4j
@Setter
@Getter
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private AppAuthProperties auth = new AppAuthProperties();
    private AppOAuth2Properties oauth2 = new AppOAuth2Properties();

    @Setter
    @Getter
    public static class AppAuthProperties {
        private String issuer = "example-spring-security-oauth2-sso";

        /**
         * token 过期时间
         */
        private long tokenExpirationSeconds = 3600L;

        private RSAPublicKey publicKey;

        private RSAPrivateKey privateKey;

        {
            try {
                publicKey = RsaKeyConverters.x509().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwt" + File.separator + "public.pub").getInputStream());
            } catch (IOException e) {
                log.error("加载JWT公钥失败", e);
                throw new RuntimeException(e);
            }

            try {
                privateKey = RsaKeyConverters.pkcs8().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwt" + File.separator + "private.key").getInputStream());
            } catch (IOException e) {
                log.error("加载JWT私钥失败", e);
                throw new RuntimeException(e);
            }
        }
    }


    @Setter
    @Getter
    public static final class AppOAuth2Properties {
        /**
         * SSO系统地址，可不配
         */
        private String domain;

        /**
         * OAuth2 登录成功后跳转系统地址
         */
        private String redirectUri;

        private List<String> authorizedRedirectUris = new ArrayList<>();
    }
}
