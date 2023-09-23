package com.metropolitan.IT355pzback.controller;

import com.metropolitan.IT355pzback.model.Telefon;
import com.metropolitan.IT355pzback.service.TelefonService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials = "true")
@RestController
@RequestMapping("/api/telefoni")
@AllArgsConstructor
public class TelefonController {

    private final TelefonService telefonService;

    @GetMapping
    public ResponseEntity<List<Telefon>> getAllTelefoni() {
        return ResponseEntity.ok(telefonService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Telefon> getTelefonById(@PathVariable("id") int id) {
        Optional<Telefon> telefon = telefonService.findById(id);

        return telefon.map(value -> new ResponseEntity<>(value, HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Telefon> createTelefon(@RequestBody Telefon telefon) {
        return ResponseEntity.ok(telefonService.save(telefon));
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Telefon> updateTelefon(@RequestBody Telefon telefon) {
        return ResponseEntity.ok(telefonService.update(telefon));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<HttpStatus> deleteTelefon(@PathVariable("id") int id) {
        try {
            telefonService.deleteById(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
