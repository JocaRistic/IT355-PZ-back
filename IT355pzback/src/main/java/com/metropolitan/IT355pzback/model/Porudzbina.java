package com.metropolitan.IT355pzback.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "porudzbine")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Porudzbina {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "id_telefon", nullable = false)
    private Telefon telefon;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "id_user", nullable = false)
    private User user;

    @Column(name = "adresa_dostave", nullable = false)
    private String adresaDostave;

    @Column(name = "postanski_broj", nullable = false)
    private String postanskiBroj;

    @Column(name = "broj_telefona", nullable = false)
    private String brojTelefona;

    @Column(name = "stanje", nullable = false)
    private String stanje;

    @Override
    public String toString() {
        return "Porudzbina{" +
                "id=" + id +
                ", telefon=" + telefon +
                ", user=" + user +
                ", adresaDostave='" + adresaDostave + '\'' +
                ", postanskiBroj='" + postanskiBroj + '\'' +
                ", brojTelefona='" + brojTelefona + '\'' +
                ", stanje='" + stanje + '\'' +
                '}';
    }
}
