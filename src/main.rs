use std::io;
use rpassword::read_password;

use std::{thread, time::Duration, io::{Write}};

fn write(text: &str, char_delay_ms: u64) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for c in text.chars() {
        print!("{}", c);
        handle.flush().unwrap();
        thread::sleep(Duration::from_millis(char_delay_ms));
    }
}

fn input(mut vari: &mut String){
    io::stdin().read_line(&mut vari).expect("unexpected error");

}

fn main() -> std::io::Result<()> {
    let users = ["admin"];
    let passwd = ["admin123"];

    let mut login = String::new();
    write("qual seu login?:\n", 50);
    input(&mut login);
    let login = login.trim();

    write("qual sua senha?:\n", 50);
    let password = read_password()?;
    let password = password.trim(); 

    if passwd.contains(&password) && users.contains(&login) {
        write("acertou a senha e o usuario", 50);
    } else {
        write("usuario ou senha incorretos", 50);
    }
    Ok(())
}
