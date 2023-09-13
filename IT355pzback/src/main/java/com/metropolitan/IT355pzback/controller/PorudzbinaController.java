package com.metropolitan.IT355pzback.controller;

import com.metropolitan.IT355pzback.model.Porudzbina;
import com.metropolitan.IT355pzback.service.PorudzbinaService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials = "true")
@RestController
@RequestMapping("/api/porudzbine")
@AllArgsConstructor
public class PorudzbinaController {

    private final PorudzbinaService porudzbinaService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Porudzbina>> getAllPorudzbine(){
        return ResponseEntity.ok(porudzbinaService.findAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Porudzbina> getPorudzbinaById(@PathVariable("id") int id) {
        Optional<Porudzbina> porudzbina = porudzbinaService.findById(id);

        return porudzbina.map(value -> new ResponseEntity<>(value, HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @GetMapping("/search/korisnik")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Porudzbina>> findByKorisnikId(@RequestParam(value = "_korisnikId") int idKorisnika) {
        try {
            List<Porudzbina> porudzbine = porudzbinaService.findByIdKorisnika(idKorisnika);

            if (porudzbine.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }
            return new ResponseEntity<>(porudzbine, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Porudzbina> createPorudzbina(@RequestBody Porudzbina porudzbina) {
        return ResponseEntity.ok(porudzbinaService.save(porudzbina));
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Porudzbina> updatePorudzbina(@RequestBody Porudzbina porudzbina) {
        return ResponseEntity.ok(porudzbinaService.update(porudzbina));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<HttpStatus> deletePorudzbina(@PathVariable("id") int id) {
        try {
            porudzbinaService.deleteById(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
