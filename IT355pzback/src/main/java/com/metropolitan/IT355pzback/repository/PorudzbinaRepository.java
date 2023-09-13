package com.metropolitan.IT355pzback.repository;

import com.metropolitan.IT355pzback.model.Porudzbina;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PorudzbinaRepository extends JpaRepository<Porudzbina, Integer> {

    List<Porudzbina> findByUser_Id(Integer id);



}
