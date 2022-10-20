package io.github.toquery.example.spring.security.oauth2.sso.core.token;

import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;

@Slf4j
@RequiredArgsConstructor
public class TokenProvider {

    private final JwtEncoder jwtEncoder;
    private final AppProperties appProperties;


    public String createToken(Authentication authentication) {
        // UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User auth2User = oAuth2AuthenticationToken.getPrincipal();

        Instant now = Instant.now();
        Instant expires = now.plusSeconds(appProperties.getAuth().getTokenExpirationSeconds());


        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(expires)
                .subject(auth2User.getAttribute("id").toString())
                // .audience(Lists.newArrayList(device))
                // .claim("uid", uid)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public Long getUserIdFromToken(String token) {
//        Claims claims = Jwts.parser()
//                .setSigningKey(appProperties.getAuth().getTokenSecret())
//                .parseClaimsJws(token)
//                .getBody();
//
//        return Long.parseLong(claims.getSubject());
        return null;
    }

    public boolean validateToken(String authToken) {
//        try {
//            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
//            return true;
//        } catch (SignatureException ex) {
//            logger.error("Invalid JWT signature");
//        } catch (MalformedJwtException ex) {
//            logger.error("Invalid JWT token");
//        } catch (ExpiredJwtException ex) {
//            logger.error("Expired JWT token");
//        } catch (UnsupportedJwtException ex) {
//            logger.error("Unsupported JWT token");
//        } catch (IllegalArgumentException ex) {
//            logger.error("JWT claims string is empty.");
//        }
        return false;
    }

}
