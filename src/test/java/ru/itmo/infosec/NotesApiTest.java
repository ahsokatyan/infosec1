package ru.itmo.infosec;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class NotesApiTest {
    private static final String PASSWORD = randomHex();
    private static final String SECRET = randomHex();

    @LocalServerPort
    private int port;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private NotesRepository repository;

    private final HttpClient client = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void environment(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:notes-test");
        registry.add("lab.jwt-secret", () -> SECRET);
        registry.add("lab.demo-password", () -> PASSWORD);
    }

    @Test
    void deniesAccessWithoutToken() throws Exception {
        var read = request("/api/data", null, null);
        assertThat(read.statusCode()).isEqualTo(401);
        assertThat(read.headers().firstValue("www-authenticate")).hasValue("Bearer");
        assertThat(request("/api/data", Map.of("text", "draft"), null).statusCode()).isEqualTo(401);
    }

    @Test
    void rejectsWrongPasswordAndUnknownLogin() throws Exception {
        var wrong = request("/auth/login", Map.of("login", "student", "password", "wrong"), null);
        var unknown = request("/auth/login", Map.of("login", "student's name", "password", PASSWORD), null);
        assertThat(wrong.statusCode()).isEqualTo(401);
        assertThat(unknown.statusCode()).isEqualTo(401);
        assertThat(unknown.body()).isEqualTo(wrong.body());
    }

    @Test
    void storesBcryptHashAndIssuesShortLivedToken() throws Exception {
        var saved = repository.findUser("student");
        assertThat(saved.passwordHash()).startsWith("$2").hasSize(60);
        assertThat(saved.passwordHash()).isNotEqualTo(PASSWORD);
        assertThat(new BCryptPasswordEncoder().matches(PASSWORD, saved.passwordHash())).isTrue();
        assertThat(login("student").get("expiresIn").asInt()).isEqualTo(900);
    }

    @Test
    void rejectsTokenWithAlteredSignature() throws Exception {
        String token = login("student").get("accessToken").asText();
        int signature = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signature) == 'A' ? 'B' : 'A';
        String changed = token.substring(0, signature) + replacement + token.substring(signature + 1);
        assertThat(request("/api/data", null, changed).statusCode()).isEqualTo(401);
    }

    @Test
    void storesRawNoteAndEscapesBothResponsesWithoutLeakingToOtherUser() throws Exception {
        var student = repository.findUser("student");
        repository.addUser("other", new BCryptPasswordEncoder(12).encode(PASSWORD));
        String token = login("student").get("accessToken").asText();
        String raw = "A & B <draft> \"quoted\" 'text'";
        String escaped = "A &amp; B &lt;draft&gt; &quot;quoted&quot; &#39;text&#39;";

        var created = request("/api/data", Map.of("text", raw), token);
        assertThat(created.statusCode()).isEqualTo(201);
        assertThat(created.headers().firstValue("x-content-type-options")).hasValue("nosniff");
        assertThat(json.readTree(created.body()).get("text").asText()).isEqualTo(escaped);
        assertThat(repository.listNotes(student.id()).getFirst().text()).isEqualTo(raw);

        var list = request("/api/data", null, token);
        assertThat(list.statusCode()).isEqualTo(200);
        assertThat(json.readTree(list.body()).get("notes").get(0).get("text").asText()).isEqualTo(escaped);
        String otherToken = login("other").get("accessToken").asText();
        assertThat(json.readTree(request("/api/data", null, otherToken).body()).get("notes").size()).isZero();
    }

    @Test
    void rejectsBlankNoteAndOversizedPassword() throws Exception {
        String token = login("student").get("accessToken").asText();
        assertThat(request("/api/data", Map.of("text", " "), token).statusCode()).isEqualTo(400);
        assertThat(request("/auth/login", Map.of("login", "student", "password", "x".repeat(73)), null)
                .statusCode()).isEqualTo(400);
    }

    private JsonNode login(String username) throws Exception {
        var result = request("/auth/login", Map.of("login", username, "password", PASSWORD), null);
        assertThat(result.statusCode()).isEqualTo(200);
        return json.readTree(result.body());
    }

    private HttpResponse<String> request(String path, Map<String, String> body, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
        if (body != null) {
            request.header("Content-Type", "application/json");
            request.POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        }
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String randomHex() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
