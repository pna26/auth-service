package store.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import store.account.AccountOut;

/** RBAC: o papel vai no JWT assinado e volta no solve. */
class JwtServiceTest {

    // chave só de teste (32 bytes fixos), nunca usada fora daqui
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private final JwtService jwt = new JwtService();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwt, "secretKey", KEY);
    }

    private static AccountOut account(String role) {
        return AccountOut.builder().id("id-1").name("Ana").email("ana@example.com").role(role).build();
    }

    @Test
    void papelDaContaVaiNoToken() {
        final String token = jwt.generate(account("ADMIN"), 60_000);
        assertEquals("id-1", jwt.getId(token));
        assertEquals("ADMIN", jwt.getRole(token));
    }

    @Test
    void contaSemPapelViraUser() {
        assertEquals("USER", jwt.getRole(jwt.generate(account(null), 60_000)));
    }

    @Test
    void tokenAntigoSemClaimRoleViraUser() {
        final SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(KEY));
        final String antigo = Jwts.builder().id("id-1")
            .expiration(new Date(System.currentTimeMillis() + 60_000))
            .signWith(key).compact();
        assertEquals("USER", jwt.getRole(antigo));
    }

    @Test
    void trocarOPapelNoPayloadInvalidaAAssinatura() {
        final String[] p = jwt.generate(account("USER"), 60_000).split("[.]");
        final String payload = new String(Base64.getUrlDecoder().decode(p[1]))
            .replace("\"USER\"", "\"ADMIN\"");
        final String forjado = p[0] + "."
            + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes()) + "." + p[2];
        final ResponseStatusException e = assertThrows(ResponseStatusException.class, () -> jwt.getRole(forjado));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
    }

}
