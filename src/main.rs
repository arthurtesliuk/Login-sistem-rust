// ################ cabecalho ############## //
// feito por Arthurtesliuk 
// ultima vez alterado 19/06 as 17:05 
// favor caso altere trocar data e adicionar seu nome
// ######################################### //

use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng, PasswordHash}}; // para gerar e verificar hash de senha (argon2)
use std::io; // para entrada padrao
use rpassword::read_password; // para ler senha sem eco no terminal
use std::{thread, time::Duration, io::Write}; // para imprimir com efeito de maquina de escrever
use rusqlite::{params, Connection, Result}; // sqlite em rust (rusqlite)

// inicializa o banco de dados e cria a tabela users se ela nao existir
fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,            -- id autoincrement (rowid)
            username TEXT NOT NULL UNIQUE,    -- nome de usuario unico e obrigatorio
            password_hash TEXT NOT NULL       -- hash da senha (argon2) armazenado como texto
        )",
        [],
    )?;
    Ok(())
}

// registra um usuario: gera hash da senha e insere no banco
fn register_user(conn: &Connection, username: &str, password: &str) -> Result<()> {
    let hash = encriptar_hash(password); // gera hash com salt aleatorio
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)", // usa parametros para evitar injeccao sql
        params![username, hash],
    )?;
    Ok(())
}

// deleta um usuario pelo username, retorna numero de linhas removidas
fn delete_user(conn: &Connection, username: &str) -> Result<usize> {
    let affected = conn.execute("DELETE FROM users WHERE username = ?1", params![username])?;
    Ok(affected as usize)
}

// autentica um usuario: busca o hash no banco e verifica a senha fornecida
fn authenticate(conn: &Connection, username: &str, password: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT password_hash FROM users WHERE username = ?1")?; // prepara statement
    let mut rows = stmt.query(params![username])?; // executa com parametro username
    if let Some(row) = rows.next()? { // se encontrou uma linha
        let stored_hash: String = row.get(0)?; // pega a coluna 0 (password_hash)
        Ok(verificar_senha(&stored_hash, password)) // verifica a senha contra o hash
    } else {
        Ok(false) // usuario nao encontrado -> retorna falso
    }
}

// escreve texto no stdout com delay entre caracteres (efeito de maquina de escrever)
// uso: write("texto", 50) onde 50 e o delay em ms entre cada caractere
fn write(text: &str, char_delay_ms: u64) {
    let stdout = io::stdout(); // obter handle para stdout
    let mut handle = stdout.lock(); // lock para escrita mais eficiente e segura entre threads
    for c in text.chars() { // itera pelos caracteres da string
        print!("{}", c);
        handle.flush().unwrap(); // garante que o caractere foi enviado para o terminal
        thread::sleep(Duration::from_millis(char_delay_ms)); // espera antes do proximo caractere
    }
}

// funcao auxiliar para ler uma linha do stdin e tratar erros basicos
fn input(vari: &mut String){
    io::stdin().read_line(vari).expect("unexpected error"); // le a linha e coloca em vari
}

// gera um hash argon2 para a senha dada
fn encriptar_hash(pwd: &str) -> String{
    let salt = SaltString::generate(&mut OsRng); // gera salt aleatorio usando o gerador do sistema
    Argon2::default() // cria instancia padrao do argon2 (parametros padrao)
        .hash_password(pwd.as_bytes(), &salt) // calcula o hash a partir da senha em bytes e do salt
        .expect("hash failed") // aborta se falhar
        .to_string() // converte o resultado para string (inclui parametros e salt)
}

// verifica se a senha em texto bate com o hash armazenado
fn verificar_senha(hash: &str, pwd: &str) -> bool {
    let parsed = PasswordHash::new(hash).expect("invalid hash format"); // parseia o hash armazenado
    Argon2::default().verify_password(pwd.as_bytes(), &parsed).is_ok() // recalcula e compara; retorna true se ok
}

// prompt simples que escreve a mensagem e retorna a linha lida ja aparada (trim)
fn prompt_trim(prompt: &str) -> String {
    write(prompt, 30); // imprime a pergunta com delay pequeno
    let mut s = String::new();
    input(&mut s); // le a resposta do usuario
    s.trim().to_string() // remove espacos em branco das pontas e retorna string
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // abre (ou cria) o arquivo main.db no diretorio atual
    let conn = Connection::open("main.db")?;
    init_db(&conn)?; // garante que a tabela users exista

    // loop principal do menu
    loop {
        write("\nqual sua escolha?\n1. registrar\n2. logar\n3. deletar usuario\n4. sair\n> ", 30); // menu com a nova opcao
        let mut choice = String::new();
        input(&mut choice);
        let choice = choice.trim();

        match choice {
            "1" => { // registrar
                // pergunta o username
                let username = prompt_trim("digite o nome do usuario (username):\n");

                // pede a senha sem eco e confirma
                write("digite a senha:\n", 30);
                let password1 = read_password()?; // nao mostra a senha ao digitar
                let password1 = password1.trim().to_string();

                write("confirme a senha:\n", 30);
                let password2 = read_password()?;
                let password2 = password2.trim().to_string();

                // verifica se as senhas conferem
                if password1 != password2 {
                    write("senhas nao conferem, registro cancelado\n", 30);
                    continue;
                }

                // tenta registrar e trata duplicata
                match register_user(&conn, &username, &password1) {
                    Ok(_) => write("usuario registrado com sucesso\n", 30),
                    Err(e) => {
                        // trata erro de unique constraint de forma generica (mensagem amigavel)
                        write("erro ao registrar (usuario pode ja existir)\n", 30);
                        // para depuracao, descomente a linha abaixo:
                        // eprintln!("register error: {}", e);
                    }
                }
            }

            "2" => { // logar / autenticar
                let username = prompt_trim("digite o nome do usuario (username):\n");
                write("digite a senha:\n", 30);
                let password = read_password()?;
                let password = password.trim();

                match authenticate(&conn, &username, &password) {
                    Ok(true) => write("autenticado com sucesso\n", 30),
                    Ok(false) => write("usuario ou senha incorretos\n", 30),
                    Err(_) => write("erro ao acessar o banco de dados\n", 30),
                }
            }

            "3" => { // deletar usuario
                let username = prompt_trim("digite o nome do usuario a ser deletado:\n");
                // confirmacao simples antes de deletar
                write(&format!("voce tem certeza que quer deletar o usuario '{}'? (s/n)\n", username), 10);
                let mut conf = String::new();
                input(&mut conf);
                let conf = conf.trim().to_lowercase();
                if conf == "s" || conf == "sim" {
                    match delete_user(&conn, &username) {
                        Ok(0) => write("usuario nao encontrado\n", 30),
                        Ok(_) => write("usuario deletado com sucesso\n", 30),
                        Err(_) => write("erro ao deletar usuario\n", 30),
                    }
                } else {
                    write("operacao cancelada\n", 30);
                }
            }

            "4" => { // sair
                write("saindo...\n", 30);
                break;
            }

            _ => {
                write("opcao invalida, escolha 1, 2, 3 ou 4\n", 30);
            }
        }
    }

    Ok(())
}
