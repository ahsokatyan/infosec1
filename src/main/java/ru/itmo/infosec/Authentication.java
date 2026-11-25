package ru.itmo.infosec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.OptionalLong;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration(proxyBeanMethods = false)
final class Authentication {
    static final int TTL_SECONDS = 900;
    private static final String ISSUER = "infosec1";
    private static final String AUDIENCE = "notes-api";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
    private final String dummyHash;
    private final MACSigner signer;
    private final MACVerifier verifier;

    Authentication(@Value("${lab.jwt-secret}") String secret) throws JOSEException {
        if (!secret.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("JWT_SECRET must be 64 hexadecimal characters");
        }
        byte[] key = HexFormat.of().parseHex(secret);
        signer = new MACSigner(key);
        verifier = new MACVerifier(key);
        byte[] random = new byte[24];
        RANDOM.nextBytes(random);
        dummyHash = bcrypt.encode(HexFormat.of().formatHex(random));
    }

    @Bean
    ApplicationRunner seedUser(NotesRepository repository,
                               @Value("${lab.demo-login}") String login,
                               @Value("${lab.demo-password}") String password) {
        return args -> {
            if (!validLogin(login)) throw new IllegalArgumentException("Invalid DEMO_LOGIN");
            if (repository.findUser(login) != null) return;
            if (!validPassword(password) || password.length() < 12) {
                throw new IllegalArgumentException("Set DEMO_PASSWORD to 12 or more characters, at most 72 UTF-8 bytes");
            }
            repository.addUser(login, bcrypt.encode(password));
        };
    }

    static boolean validLogin(String login) {
        return login != null && !login.isBlank() && login.length() <= 64;
    }

    static boolean validPassword(String password) {
        return password != null && !password.isEmpty()
                && password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }

    boolean verifyPassword(NotesRepository.User user, String password) {
        boolean match = bcrypt.matches(password, user == null ? dummyHash : user.passwordHash());
        return match && user != null;
    }

    String issue(long userId) {
        Instant now = Instant.now();
        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
                new JWTClaimsSet.Builder().issuer(ISSUER).audience(AUDIENCE).subject(Long.toString(userId))
                        .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(TTL_SECONDS))).build());
        try {
            token.sign(signer);
            return token.serialize();
        } catch (JOSEException error) {
            throw new IllegalStateException("JWT signing failed", error);
        }
    }

    OptionalLong verifyToken(String header) {
        if (header == null || header.length() > 2048 || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return OptionalLong.empty();
        }
        try {
            SignedJWT token = SignedJWT.parse(header.substring(7));
            if (!JWSAlgorithm.HS256.equals(token.getHeader().getAlgorithm()) || !token.verify(verifier)) {
                return OptionalLong.empty();
            }
            JWTClaimsSet claims = token.getJWTClaimsSet();
            Date expires = claims.getExpirationTime();
            Date issued = claims.getIssueTime();
            Instant now = Instant.now();
            if (!ISSUER.equals(claims.getIssuer()) || !claims.getAudience().contains(AUDIENCE)
                    || issued == null || issued.toInstant().isAfter(now)
                    || expires == null || !expires.toInstant().isAfter(now)
                    || expires.toInstant().isAfter(issued.toInstant().plusSeconds(TTL_SECONDS))) {
                return OptionalLong.empty();
            }
            long id = Long.parseLong(claims.getSubject());
            return id > 0 ? OptionalLong.of(id) : OptionalLong.empty();
        } catch (ParseException | JOSEException | IllegalArgumentException error) {
            return OptionalLong.empty();
        }
    }
}
