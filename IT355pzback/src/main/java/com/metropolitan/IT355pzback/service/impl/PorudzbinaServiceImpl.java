package com.metropolitan.IT355pzback.service.impl;

import com.metropolitan.IT355pzback.model.Porudzbina;
import com.metropolitan.IT355pzback.repository.PorudzbinaRepository;
import com.metropolitan.IT355pzback.service.PorudzbinaService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PorudzbinaServiceImpl implements PorudzbinaService {

    private final PorudzbinaRepository porudzbinaRepository;

    @Override
    public List<Porudzbina> findAll() {
        return porudzbinaRepository.findAll();
    }

    @Override
    public List<Porudzbina> findByIdKorisnika(Integer id) {
        return  porudzbinaRepository.findByUser_Id(id);
    }

    @Override
    public Optional<Porudzbina> findById(Integer id) {
        return porudzbinaRepository.findById(id);
    }

    @Override
    public Porudzbina save(Porudzbina porudzbina) {
        return porudzbinaRepository.save(porudzbina);
    }

    @Override
    public Porudzbina update(Porudzbina porudzbina) {
        return porudzbinaRepository.save(porudzbina);
    }

    @Override
    public void deleteById(Integer id) {
        porudzbinaRepository.deleteById(id);
    }
}
