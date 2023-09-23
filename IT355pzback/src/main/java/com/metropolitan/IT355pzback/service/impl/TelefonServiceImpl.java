package com.metropolitan.IT355pzback.service.impl;

import com.metropolitan.IT355pzback.model.Telefon;
import com.metropolitan.IT355pzback.repository.TelefonRepository;
import com.metropolitan.IT355pzback.service.TelefonService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TelefonServiceImpl implements TelefonService {

    private final TelefonRepository telefonRepository;

    @Override
    public List<Telefon> findAll() {
        return telefonRepository.findAll();
    }

    @Override
    public Optional<Telefon> findById(Integer id) {
        return telefonRepository.findById(id);
    }

    @Override
    public Telefon save(Telefon telefon) {
        return telefonRepository.save(telefon);
    }

    @Override
    public Telefon update(Telefon telefon) {
        return telefonRepository.save(telefon);
    }

    @Override
    public void deleteById(Integer id) {
        telefonRepository.deleteById(id);
    }
}
