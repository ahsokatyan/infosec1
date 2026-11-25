package ru.itmo.infosec;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
class NotesController {
    private final NotesRepository repository;
    private final Authentication auth;

    NotesController(NotesRepository repository, Authentication auth) {
        this.repository = repository;
        this.auth = auth;
    }

    record Credentials(String login, String password) {}
    record NoteInput(String text) {}
    record Token(String accessToken, String tokenType, int expiresIn) {}

    @PostMapping(path = "/auth/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> login(@RequestBody Credentials credentials) {
        if (!Authentication.validLogin(credentials.login()) || !Authentication.validPassword(credentials.password())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid credentials format"));
        }
        var user = repository.findUser(credentials.login());
        if (!auth.verifyPassword(user, credentials.password())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials"));
        }
        return ResponseEntity.ok(new Token(auth.issue(user.id()), "Bearer", Authentication.TTL_SECONDS));
    }

    @GetMapping("/api/data")
    Map<String, List<NotesRepository.Note>> list(@RequestAttribute(ApiFilter.OWNER_ID) long ownerId) {
        return Map.of("notes", repository.listNotes(ownerId).stream().map(NotesController::publicNote).toList());
    }

    @PostMapping(path = "/api/data", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> add(@RequestAttribute(ApiFilter.OWNER_ID) long ownerId, @RequestBody NoteInput input) {
        String text = input.text();
        if (text == null || text.isBlank() || text.length() > 500) {
            return ResponseEntity.badRequest().body(Map.of("error", "Note text must contain 1 to 500 characters"));
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(publicNote(repository.addNote(ownerId, text)));
    }

    private static NotesRepository.Note publicNote(NotesRepository.Note note) {
        return new NotesRepository.Note(note.id(), HtmlUtils.htmlEscape(note.text(), StandardCharsets.UTF_8.name()));
    }
}
