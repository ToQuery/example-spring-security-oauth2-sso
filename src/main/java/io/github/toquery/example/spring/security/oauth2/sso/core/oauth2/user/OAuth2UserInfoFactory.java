package io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.user;

import io.github.toquery.example.spring.security.oauth2.sso.core.exception.OAuth2Exception;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2Exception("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
