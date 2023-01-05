package io.github.toquery.example.spring.security.oauth2.sso.core.security;

import io.github.toquery.example.spring.security.oauth2.sso.core.exception.OAuth2Exception;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import io.github.toquery.example.spring.security.oauth2.sso.core.util.CookieUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
public class AppOAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    private final AppProperties appProperties;


    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME).map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new OAuth2Exception("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

//        现使用SSO发放的 IdToken ， 不需要自己生成
//        NimbusJwtClientAuthenticationParametersConverter<> nimbusJwtClientAuthenticationParametersConverter = new NimbusJwtClientAuthenticationParametersConverter<>();
//        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
//
//        Instant issuedAt = Instant.now();
//        Instant expiresAt = issuedAt.plus(Duration.ofHours(6));
//
//        JwtClaimsSet claimsBuilder = JwtClaimsSet.builder()
//                .issuer(clientRegistration.getClientId())
//                .subject(clientRegistration.getClientId())
//                .audience(Collections.singletonList(clientRegistration.getProviderDetails().getTokenUri()))
//                .id(UUID.randomUUID().toString())
//                .claim("roles", List.of("admin"))
//                .claim("mc", List.of("messages", "stores"))
//                .issuedAt(issuedAt)
//                .notBefore(issuedAt)
//                .expiresAt(expiresAt)
//                .build();
//
//        Jwt jws = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder));

        String accessToken = ""; // jws.getTokenValue();

        // 判断类型，直接返回认证中心提供的token信息
        if (authentication instanceof OAuth2AuthenticationToken auth2AuthenticationToken && auth2AuthenticationToken.getPrincipal() instanceof OidcUser oidcUser) {
            accessToken = oidcUser.getIdToken().getTokenValue();
        } else {
            // 否则不支持其他类型的认证
            throw new OAuth2Exception("Sorry! Unsupported Authentication Type " + authentication.getClass().getName() + " , Principal Type" + authentication.getPrincipal().getClass());
        }

        Cookie accessTokenCookie = new Cookie("ACCESS_TOKEN", accessToken);
        response.addCookie(accessTokenCookie);

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(targetUrl);
        if (accessToken != null && !"".equalsIgnoreCase(accessToken)) {
            uriComponentsBuilder.queryParam("access_token", accessToken);
        }
        return uriComponentsBuilder.build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort();
                });
    }
}
