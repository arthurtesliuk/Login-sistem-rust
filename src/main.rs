use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng, PasswordHash}}; // para fazer um hash da senha
use std::io; // para inputs
use rpassword::read_password; // para nao mostrar o passworrd com echo  
use std::{thread, time::Duration, io::Write}; // modulos para contagem de tempo

// imports para uso posterior

fn write(text: &str, char_delay_ms: u64) { // uma funcao para escrever como se fosse na maquina de escrever
    let stdout = io::stdout(); // simplificando io::stdout para stdout
    let mut handle = stdout.lock(); // implementa o lock
    for c in text.chars() { // cicla entre os caracteres e printa eles
        print!("{}", c);
        handle.flush().unwrap();
        thread::sleep(Duration::from_millis(char_delay_ms)); // espera um delay para printar o proximo caractere
    }
}

fn input(vari: &mut String){ // simplificando o io::stdin().read_line(vari).expect("unexpected error"); para somente input() igual python
    io::stdin().read_line(vari).expect("unexpected error");
}

fn encriptar_hash(pwd: &str) -> String{ // encriptacao em hash
    let salt = SaltString::generate(&mut OsRng); // gera um salt para maior dificuldade de decriptacao
    let argon2 = Argon2::default(); // outro salt
    argon2.hash_password(pwd.as_bytes(), &salt)// retorna o pwd (password) como bytes
        .expect("hash failed")// caso falhe
        .to_string() // transformar devolta para string
}

fn verificar_senha(hash: &str, pwd: &str) -> bool { // recebe o hash armazenado e retorna true se bate com hash
    let parsed = PasswordHash::new(hash).expect("invalid hash format");
    Argon2::default().verify_password(pwd.as_bytes(), &parsed).is_ok()
} // aborta caso esteja no formato hash errado

fn main() -> std::io::Result<()> {
    // simula hash armazenado para "admin123"
    let stored_user = "admin";
    let stored_hash = encriptar_hash("admin123"); // em app real, recupere do DB

    let mut login = String::new();
    write("qual seu login?:\n", 50);
    input(&mut login);
    let login = login.trim();

    write("qual sua senha?:\n", 50);
    let password = read_password()?;
    let password = password.trim();

    if login == stored_user && verificar_senha(&stored_hash, password) {
        write("acertou a senha e o usuario\n", 50);
    } else {
        write("usuario ou senha incorretos\n", 50);
    }
    Ok(())
}
