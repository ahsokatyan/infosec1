package ru.itmo.infosec;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;
import java.util.Map;

@Repository
class NotesRepository {
    private final JdbcTemplate jdbc;
    private final SimpleJdbcInsert insertNote;

    NotesRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        this.insertNote = new SimpleJdbcInsert(jdbc)
                .withTableName("notes")
                .usingColumns("owner_id", "note_text")
                .usingGeneratedKeyColumns("id");
    }

    record User(long id, String passwordHash) {}
    record Note(long id, String text) {}

    User findUser(String login) {
        return jdbc.query("SELECT id, password_hash FROM app_users WHERE login = ?",
                (rs, row) -> new User(rs.getLong("id"), rs.getString("password_hash")), login)
                .stream().findFirst().orElse(null);
    }

    void addUser(String login, String hash) {
        jdbc.update("INSERT INTO app_users (login, password_hash) VALUES (?, ?)", login, hash);
    }

    List<Note> listNotes(long ownerId) {
        return jdbc.query("""
                SELECT id, note_text FROM notes WHERE owner_id = ?
                ORDER BY id DESC FETCH FIRST 100 ROWS ONLY
                """, (rs, row) -> new Note(rs.getLong("id"), rs.getString("note_text")), ownerId);
    }

    Note addNote(long ownerId, String text) {
        Number id = insertNote.executeAndReturnKey(Map.of("owner_id", ownerId, "note_text", text));
        return new Note(id.longValue(), text);
    }
}
