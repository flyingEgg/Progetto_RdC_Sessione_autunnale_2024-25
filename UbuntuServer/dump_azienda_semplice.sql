-- ************************************************************
-- DATABASE: azienda
-- USATO PER TEST SQL INJECTION E SURICATA
-- ************************************************************

DROP DATABASE IF EXISTS azienda;
CREATE DATABASE azienda CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE azienda;

-- ************************************************************
-- Tabella: dipendenti
-- ************************************************************
CREATE TABLE dipendenti (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(50) NOT NULL,
    cognome VARCHAR(50) NOT NULL,
    ruolo VARCHAR(50),
    stipendio DECIMAL(10,2),
    email VARCHAR(100) UNIQUE,
    data_assunzione DATE
);

INSERT INTO dipendenti (nome, cognome, ruolo, stipendio, email, data_assunzione) VALUES
('Mario', 'Rossi', 'Sviluppatore Frontend', 3500.00, 'mario.rossi@azienda.it', '2020-03-15'),
('Luca', 'Bianchi', 'Project Manager', 5000.00, 'luca.bianchi@azienda.it', '2019-06-10'),
('Anna', 'Verdi', 'UX Designer', 3800.00, 'anna.verdi@azienda.it', '2021-01-20'),
('Giulia', 'Neri', 'Data Analyst', 4000.00, 'giulia.neri@azienda.it', '2020-11-05'),
('Paolo', 'Gialli', 'QA Tester', 3200.00, 'paolo.gialli@azienda.it', '2022-02-14'),
('Silvia', 'Mori', 'Sviluppatore Backend', 3700.00, 'silvia.mori@azienda.it', '2019-09-01');


-- ************************************************************
-- Tabella: clienti
-- ************************************************************
CREATE TABLE clienti (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome_azienda VARCHAR(100),
    settore VARCHAR(50),
    fatturato_annuo DECIMAL(12,2),
    contatto_nome VARCHAR(100),
    email VARCHAR(100),
    telefono VARCHAR(20)
);

INSERT INTO clienti (nome_azienda, settore, fatturato_annuo, contatto_nome, email, telefono) VALUES
('TechNova SRL', 'IT', 1200000.00, 'Marco Ferrari', 'marco.ferrari@technova.it', '+39 02 1234567'),
('GreenFuture SPA', 'Energia', 850000.00, 'Elena Ricci', 'elena.ricci@greenfuture.it', '+39 06 9876543'),
('WebDesign Studio', 'Marketing', 320000.00, 'Carlo Monti', 'carlo.monti@webdesign.it', '+39 011 555666');


-- ************************************************************
-- Tabella: progetti
-- ************************************************************
CREATE TABLE progetti (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100),
    cliente_id INT,
    budget DECIMAL(12,2),
    stato VARCHAR(20), -- 'In corso', 'Completato', 'Pianificato'
    data_inizio DATE,
    data_fine DATE,
    FOREIGN KEY (cliente_id) REFERENCES clienti(id)
);

INSERT INTO progetti (nome, cliente_id, budget, stato, data_inizio, data_fine) VALUES
('Sito E-Commerce', 1, 45000.00, 'In corso', '2023-09-01', '2024-02-28'),
('App Mobile Green', 2, 62000.00, 'In corso', '2023-11-01', '2024-05-31'),
('Dashboard Analytics', 3, 28000.00, 'Completato', '2023-01-15', '2023-06-30');


-- ************************************************************
-- Tabella: utenti (per login web - vulnerabile a SQLi)
-- ************************************************************
CREATE TABLE utenti (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    ruolo VARCHAR(20) -- 'admin', 'user'
);

-- Password di esempio: "password123" (hashata con bcrypt o simile)
-- Esempio di hash reale (non è 'password123' in chiaro!)
INSERT INTO utenti (username, password_hash, ruolo) VALUES
('admin', '$2y$10$EPnOOBjOxY712V5Z93Q7AO8uXW1q5VJZzZ6a1b2c3d4e5f6g7h8i9', 'admin'),
('mario.rossi', '$2y$10$aBcDeFgHiJkLmNoPqRsTuUvWxYz1234567890AbCdEfGhIjKlMnOp', 'user');


-- ************************************************************
-- Indici per prestazioni
-- ************************************************************
ALTER TABLE progetti ADD INDEX idx_stato (stato);
ALTER TABLE dipendenti ADD INDEX idx_ruolo (ruolo);