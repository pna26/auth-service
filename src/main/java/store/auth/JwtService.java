package store.auth;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import store.account.AccountOut;

@Service
public class JwtService {

    public static final String ROLE_CLAIM = "role";
    public static final String DEFAULT_ROLE = "USER";

    @Value("${store.jwt.secretKey}")
    private String secretKey;

    public String generate(AccountOut account, long duration) {

        Date now = new Date();
        return Jwts.builder()
            .header().and()
            .id(account.id())
            .issuer("Insper::PMA")
            .claims(Map.of(
                "email", account.email(),
                // RBAC: o gateway decide o acesso pelo papel (sem papel = USER)
                ROLE_CLAIM, roleOf(account)
            ))
            .signWith(getKey())
            .subject(account.name())
            .notBefore(now)
            .expiration(new Date(now.getTime() + duration))
            .compact();
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey));
    }

    public String getId(String jwt) {
        return parse(jwt).getId();
    }

    /** papel gravado no token; token sem o claim (emitido antes do RBAC) vale USER. */
    public String getRole(String jwt) {
        final String role = parse(jwt).get(ROLE_CLAIM, String.class);
        return role == null || role.isBlank() ? DEFAULT_ROLE : role;
    }

    private Claims parse(String jwt) {
        try {
            JwtParser parser = Jwts.parser().verifyWith(getKey()).build();
            // confere a assinatura, o nbf e o exp: senão, JwtException
            return parser.parseSignedClaims(jwt).getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Invalid token");
        }
    }

    private static String roleOf(AccountOut account) {
        return account.role() == null || account.role().isBlank()
            ? DEFAULT_ROLE
            : account.role();
    }

}
