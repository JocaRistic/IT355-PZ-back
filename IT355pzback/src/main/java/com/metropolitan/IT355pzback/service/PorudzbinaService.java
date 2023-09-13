package com.metropolitan.IT355pzback.service;

import com.metropolitan.IT355pzback.model.Porudzbina;

import java.util.List;
import java.util.Optional;

public interface PorudzbinaService {

    List<Porudzbina> findAll();

    List<Porudzbina> findByIdKorisnika(Integer id);

    Optional<Porudzbina> findById(Integer id);

    Porudzbina save(Porudzbina porudzbina);

    Porudzbina update(Porudzbina porudzbina);

    void deleteById(Integer id);

}
