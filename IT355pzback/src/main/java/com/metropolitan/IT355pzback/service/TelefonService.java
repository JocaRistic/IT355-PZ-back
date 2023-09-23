package com.metropolitan.IT355pzback.service;

import com.metropolitan.IT355pzback.model.Telefon;

import java.util.List;
import java.util.Optional;

public interface TelefonService {

    List<Telefon> findAll();

    Optional<Telefon> findById(Integer id);

    Telefon save(Telefon telefon);

    Telefon update(Telefon telefon);

    void deleteById(Integer id);

}
