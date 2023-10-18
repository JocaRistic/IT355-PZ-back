package com.metropolitan.IT355pzback.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "telefoni")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Telefon {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "brend", nullable = false)
    private String brend;

    @Column(name = "model", nullable = false)
    private String model;

    @Column(name = "dijagonala_ekrana", nullable = false)
    private String dijagonalaEkrana;

    @Column(name = "ram", nullable = false)
    private String ram;

    @Column(name = "memorija", nullable = false)
    private String memorija;

    @Column(name = "kamera", nullable = false)
    private String kamera;

    @Column(name = "baterija", nullable = false)
    private String baterija;

    @Column(name = "rezolucija", nullable = false)
    private String rezolucija;

    @Column(name = "cena", nullable = false)
    private double cena;

    @Column(name = "slika_url", nullable = false)
    private String slikaUrl;

    @Override
    public String toString() {
        return "Telefon{" +
                "id=" + id +
                ", brend='" + brend + '\'' +
                ", model='" + model + '\'' +
                ", dijagonalaEkrana='" + dijagonalaEkrana + '\'' +
                ", ram='" + ram + '\'' +
                ", memorija='" + memorija + '\'' +
                ", kamera='" + kamera + '\'' +
                ", baterija='" + baterija + '\'' +
                ", rezolucija='" + rezolucija + '\'' +
                ", cena=" + cena +
                ", slikaUrl='" + slikaUrl + '\'' +
                '}';
    }
}
