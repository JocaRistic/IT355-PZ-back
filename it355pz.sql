-- phpMyAdmin SQL Dump
-- version 5.1.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 19, 2023 at 01:10 AM
-- Server version: 10.4.18-MariaDB
-- PHP Version: 8.0.5

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `it355pz`
--

-- --------------------------------------------------------

--
-- Table structure for table `korisnici`
--

CREATE TABLE `korisnici` (
  `id` int(11) NOT NULL,
  `ime` varchar(20) NOT NULL,
  `prezime` varchar(20) NOT NULL,
  `username` varchar(20) NOT NULL,
  `email` varchar(50) NOT NULL,
  `password` varchar(120) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `korisnici`
--

INSERT INTO `korisnici` (`id`, `ime`, `prezime`, `username`, `email`, `password`) VALUES
(9, 'Admin', 'Administratovic', 'admin', 'admin@gmail.com', '$2a$10$9kPemZ9Foc5HGAYcaAZgJeEzV.b7MSGepUu9sZeTtL8Z.Qj/fa0Se'),
(10, 'Jovica', 'Ristic', 'joca', 'joca@gmail.com', '$2a$10$F6ymMp1P.U2LOSnlLbrRSuwnI7t0OIMVJ3qJKqYuVykWdFGvP9eqW'),
(11, 'Nikola', 'Nikolic', 'nikola', 'nikola@gmail.com', '$2a$10$8sD1Mm1A1rl9VSiGKPzojuckiQYgL3ZQLxA02r0XfzqryD1t27twW'),
(12, 'Ime', 'Prezime', 'username', 'email@gmail.com', '$2a$10$JmDw1y6kyZJhfe8bKtHnF.ykgw6V26LZK3ZVI3CmaRb7uYjrdkcwS');

-- --------------------------------------------------------

--
-- Table structure for table `porudzbine`
--

CREATE TABLE `porudzbine` (
  `id` int(11) NOT NULL,
  `id_telefon` int(11) NOT NULL,
  `id_user` int(11) NOT NULL,
  `adresa_dostave` varchar(255) NOT NULL,
  `broj_telefona` varchar(255) NOT NULL,
  `postanski_broj` varchar(255) NOT NULL,
  `stanje` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `porudzbine`
--

INSERT INTO `porudzbine` (`id`, `id_telefon`, `id_user`, `adresa_dostave`, `broj_telefona`, `postanski_broj`, `stanje`) VALUES
(2, 5, 10, 'Leskovac', '0612323232', '16000', 'isporuceno'),
(10, 17, 11, 'Beograd', '3424324324', '18000', 'isporuceno'),
(12, 5, 12, 'Beograd', '0612323423', '18000', 'na cekanju');

-- --------------------------------------------------------

--
-- Table structure for table `role`
--

CREATE TABLE `role` (
  `id` int(11) NOT NULL,
  `naziv` enum('ROLE_ADMIN','ROLE_USER') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `role`
--

INSERT INTO `role` (`id`, `naziv`) VALUES
(1, 'ROLE_USER'),
(2, 'ROLE_ADMIN');

-- --------------------------------------------------------

--
-- Table structure for table `telefoni`
--

CREATE TABLE `telefoni` (
  `cena` double NOT NULL,
  `id` int(11) NOT NULL,
  `baterija` varchar(255) NOT NULL,
  `brend` varchar(255) NOT NULL,
  `dijagonala_ekrana` varchar(255) NOT NULL,
  `kamera` varchar(255) NOT NULL,
  `memorija` varchar(255) NOT NULL,
  `model` varchar(255) NOT NULL,
  `ram` varchar(255) NOT NULL,
  `rezolucija` varchar(255) NOT NULL,
  `slika_url` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `telefoni`
--

INSERT INTO `telefoni` (`cena`, `id`, `baterija`, `brend`, `dijagonala_ekrana`, `kamera`, `memorija`, `model`, `ram`, `rezolucija`, `slika_url`) VALUES
(99.999, 5, '4360 mAh', 'Huawei', '6.66', '64 Mpix + 2 Mpix + 2 Mpix / 13 Mpix', '256 GB', 'P50 Pro 256GB Black', '8 GB', '2700 x 1228', 'https://cdn2.mobilnisvet.com/oQK4IKiyFCK2btj9J2F8YoV8Qxu_zZyXG61BsD-SauM/sm:1/sh:1/el:0/q:85/wm:0.2:re:0:0:0.5/rs:fill:360:779/czM6Ly9tb2JpbG5pc3ZldGNvbS8yMDIxLzEvMTI3L2wwNzEyMDJ4YnZzbnRtNmdmcjQ1LzIvdGYucG5n.webp'),
(89.999, 17, '4800 mAh', 'Honor', '6.67', '64 Mpix + 2 Mpix + 2 Mpix / 13 Mpix kam', '128 GB', '70', '8 GB', '2400 x 1080', 'https://cdn2.mobilnisvet.com/TmCUAsx6B6OI6GcAHkLFI-45klxEt80PyxCHQ8oSVR8/sm:1/sh:1/el:0/q:85/wm:0.2:re:0:0:0.5/rs:fill:360:789/czM6Ly9tb2JpbG5pc3ZldGNvbS8yMDIyLzEvMTI3LzRyZHZmbHZidDR5NTNjeThxNGJ2LzIvdGYucG5n.webp'),
(32323, 20, '3232', 'kjasfnkjdf', '32', '323', '323', 'kfnak', '32', '3823', 'https://noviapartmani.com/public/upload/apartments/2022/09/beograd-vozdovac-apartman-beran-1-7-218_featured_thumb.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `user_roles`
--

CREATE TABLE `user_roles` (
  `role_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `user_roles`
--

INSERT INTO `user_roles` (`role_id`, `user_id`) VALUES
(2, 9),
(1, 10),
(1, 11),
(1, 12);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `korisnici`
--
ALTER TABLE `korisnici`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `UKfnhlgpdv9nwggcetnb4hadcdi` (`username`),
  ADD UNIQUE KEY `UKl3fojej3v08wwlnj7bxe6bl9q` (`email`);

--
-- Indexes for table `porudzbine`
--
ALTER TABLE `porudzbine`
  ADD PRIMARY KEY (`id`),
  ADD KEY `FKcaiku9vumbajq1aq66eif119y` (`id_user`),
  ADD KEY `FK7ov3irmmdg3up8xsghbc8anlu` (`id_telefon`);

--
-- Indexes for table `role`
--
ALTER TABLE `role`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `telefoni`
--
ALTER TABLE `telefoni`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `user_roles`
--
ALTER TABLE `user_roles`
  ADD KEY `FKrhfovtciq1l558cw6udg0h0d3` (`role_id`),
  ADD KEY `FK8sl2w6nqy2ksqv03hvea9lc23` (`user_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `korisnici`
--
ALTER TABLE `korisnici`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `porudzbine`
--
ALTER TABLE `porudzbine`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT for table `telefoni`
--
ALTER TABLE `telefoni`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `porudzbine`
--
ALTER TABLE `porudzbine`
  ADD CONSTRAINT `FK7ov3irmmdg3up8xsghbc8anlu` FOREIGN KEY (`id_telefon`) REFERENCES `telefoni` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `FKcaiku9vumbajq1aq66eif119y` FOREIGN KEY (`id_user`) REFERENCES `korisnici` (`id`);

--
-- Constraints for table `user_roles`
--
ALTER TABLE `user_roles`
  ADD CONSTRAINT `FK8sl2w6nqy2ksqv03hvea9lc23` FOREIGN KEY (`user_id`) REFERENCES `korisnici` (`id`),
  ADD CONSTRAINT `FKrhfovtciq1l558cw6udg0h0d3` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
