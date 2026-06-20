// ################ cabecalho ############## //
// feito por arthurtesliuk
// ultima vez alterado 20/06 as 07:35
// alterações:
// - sessão em memória para saber quem está logado
// - menu dinâmico: opções admin só aparecem para admin
// - não permite deletar o usuário "admin"
// - admin pode renomear qualquer usuário
// - usuário normal só pode renomear a si mesmo
// - comentários restaurados e adicionais (todos em minúsculas)
// ######################################### //

use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng, PasswordHash}}; // argon2 para hash de senha
use std::io; // entrada/saída padrão
use rpassword::read_password; // leitura de senha sem eco no terminal
use std::{thread, time::Duration, io::Write}; // para efeito de máquina de escrever (delay na impressão)
use rusqlite::{params, Connection, Result}; // sqlite (rusqlite)

// inicializa o banco de dados e cria a tabela users se ela não existir
fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "create table if not exists users (
            id integer primary key,
            username text not null unique,
            password_hash text not null
        )",
        [],
    )?;
    Ok(())
}

// registra um usuário: gera hash da senha e insere no banco
fn register_user(conn: &Connection, username: &str, password: &str) -> Result<()> {
    let hash = encriptar_hash(password); // gera hash com salt aleatório
    conn.execute(
        "insert into users (username, password_hash) values (?1, ?2)",
        params![username, hash],
    )?;
    Ok(())
}

// deleta um usuário pelo username, retorna número de linhas removidas
fn delete_user(conn: &Connection, username: &str) -> Result<usize> {
    let affected = conn.execute("delete from users where username = ?1", params![username])?;
    Ok(affected as usize)
}

// renomeia um usuário: atualiza username, retorna número de linhas afetadas
fn rename_user(conn: &Connection, old_username: &str, new_username: &str) -> Result<usize> {
    let affected = conn.execute(
        "update users set username = ?1 where username = ?2",
        params![new_username, old_username],
    )?;
    Ok(affected as usize)
}

// autentica um usuário: busca o hash no banco e verifica a senha fornecida
fn authenticate(conn: &Connection, username: &str, password: &str) -> Result<bool> {
    let mut stmt = conn.prepare("select password_hash from users where username = ?1")?;
    let mut rows = stmt.query(params![username])?;
    if let Some(row) = rows.next()? {
        let stored_hash: String = row.get(0)?;
        Ok(verificar_senha(&stored_hash, password))
    } else {
        Ok(false) // usuário não encontrado
    }
}

// escreve texto no stdout com delay entre caracteres (efeito de máquina de escrever)
// uso: write("texto", 50) onde 50 é o delay em ms entre cada caractere
fn write(text: &str, char_delay_ms: u64) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for c in text.chars() {
        print!("{}", c);
        handle.flush().unwrap();
        thread::sleep(Duration::from_millis(char_delay_ms));
    }
}

// função auxiliar para ler uma linha do stdin e tratar erros básicos
fn input(vari: &mut String){
    io::stdin().read_line(vari).expect("unexpected error");
}

// gera um hash argon2 para a senha dada
fn encriptar_hash(pwd: &str) -> String{
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pwd.as_bytes(), &salt)
        .expect("hash failed")
        .to_string()
}

// verifica se a senha em texto bate com o hash armazenado
fn verificar_senha(hash: &str, pwd: &str) -> bool {
    let parsed = PasswordHash::new(hash).expect("invalid hash format");
    Argon2::default().verify_password(pwd.as_bytes(), &parsed).is_ok()
}

// prompt simples que escreve a mensagem e retorna a linha lida já aparada (trim)
fn prompt_trim(prompt: &str) -> String {
    write(prompt, 30);
    let mut s = String::new();
    input(&mut s);
    s.trim().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // abre (ou cria) o arquivo main.db no diretório atual
    let conn = Connection::open("main.db")?;
    init_db(&conn)?; // garante que a tabela users exista

    // sessão simples: guarda o username autenticado se houver e flag de admin
    let mut session_user: Option<String> = None;
    let mut session_is_admin: bool = false;

    // loop principal do menu
    loop {
        // menu dinâmico: inclui opção admin somente se session_is_admin == true
        if session_is_admin {
            write("\nqual sua escolha?\n1. registrar\n2. logar\n3. deletar usuario\n4. renomear usuario\n5. quem sou eu\n6. listar usuarios (admin)\nq. sair\n> ", 30);
        } else {
            write("\nqual sua escolha?\n1. registrar\n2. logar\n3. deletar usuario\n4. renomear usuario\n5. quem sou eu\nq. sair\n> ", 30);
        }

        let mut choice = String::new();
        input(&mut choice);
        let choice = choice.trim();

        match choice {
            "1" => { // registrar
                // pergunta o username
                let username = prompt_trim("digite o nome do usuario (username):\n");

                // pede a senha sem eco e confirma
                write("digite a senha:\n", 30);
                let password1 = read_password()?;
                let password1 = password1.trim().to_string();

                write("confirme a senha:\n", 30);
                let password2 = read_password()?;
                let password2 = password2.trim().to_string();

                // verifica se as senhas conferem
                if password1 != password2 {
                    write("senhas nao conferem, registro cancelado\n", 30);
                    continue;
                }

                // tenta registrar e trata duplicata generica
                match register_user(&conn, &username, &password1) {
                    Ok(_) => write("usuario registrado com sucesso\n", 30),
                    Err(_) => write("erro ao registrar (usuario pode ja existir)\n", 30),
                }
            }

            "2" => { // logar / autenticar
                let username = prompt_trim("digite o nome do usuario (username):\n");
                write("digite a senha:\n", 30);
                let password = read_password()?;
                let password = password.trim();

                match authenticate(&conn, &username, &password) {
                    Ok(true) => {
                        write("autenticado com sucesso\n", 30);
                        session_user = Some(username.clone()); // salva username na sessão
                        session_is_admin = username == "admin"; // considera 'admin' como administrador
                    }
                    Ok(false) => write("usuario ou senha incorretos\n", 30),
                    Err(_) => write("erro ao acessar o banco de dados\n", 30),
                }
            }

            "3" => { // deletar usuario
                let username = prompt_trim("digite o nome do usuario a ser deletado:\n");

                // impedir deletar admin explicitamente
                if username == "admin" {
                    write("acao proibida: nao e possivel deletar o usuario 'admin'\n", 30);
                    continue;
                }

                // confirmacao simples antes de deletar
                write(&format!("voce tem certeza que quer deletar o usuario '{}'? (s/n)\n", username), 10);
                let mut conf = String::new();
                input(&mut conf);
                let conf = conf.trim().to_lowercase();
                if conf == "s" || conf == "sim" {
                    match delete_user(&conn, &username) {
                        Ok(0) => write("usuario nao encontrado\n", 30),
                        Ok(_) => {
                            write("usuario deletado com sucesso\n", 30);
                            // se o usuario deletado era o logado, desloga
                            if let Some(ref u) = session_user {
                                if u == &username {
                                    session_user = None;
                                    session_is_admin = false;
                                    write("sessao encerrada (usuario deletado)\n", 30);
                                }
                            }
                        }
                        Err(_) => write("erro ao deletar usuario\n", 30),
                    }
                } else {
                    write("operacao cancelada\n", 30);
                }
            }

            "4" => { // renomear usuario
                // renomeacao: se admin pode renomear qualquer usuario;
                // se usuario normal, so pode renomear a si mesmo
                if session_is_admin {
                    // admin escolhe quem renomear
                    let target = prompt_trim("digite o nome do usuario a ser renomeado:\n");
                    // nao permitir renomear admin para algo diferente (protege admin)
                    if target == "admin" {
                        write("acao proibida: nao e permitido renomear o usuario 'admin'\n", 30);
                        continue;
                    }
                    let new_name = prompt_trim(&format!("digite o novo nome para '{}':\n", target));
                    // checar se novo_name eh 'admin' (nao permitir sobrescrever admin)
                    if new_name == "admin" {
                        write("acao proibida: nao e permitido usar o nome 'admin'\n", 30);
                        continue;
                    }
                    match rename_user(&conn, &target, &new_name) {
                        Ok(0) => write("usuario alvo nao encontrado\n", 30),
                        Ok(_) => write("usuario renomeado com sucesso\n", 30),
                        Err(_) => write("erro ao renomear usuario (novo nome pode ja existir)\n", 30),
                    }
                } else {
                    // usuario normal: so pode renomear a si mesmo
                    match &session_user {
                        Some(u) => {
                            // nao permitir renomear admin (caso improvavel: se session_user == admin, session_is_admin seria true)
                            if u == "admin" {
                                write("acao proibida: nao e permitido renomear o usuario 'admin'\n", 30);
                                continue;
                            }
                            let new_name = prompt_trim("digite seu novo nome de usuario:\n");
                            if new_name == "admin" {
                                write("acao proibida: nao e permitido usar o nome 'admin'\n", 30);
                                continue;
                            }
                            match rename_user(&conn, &u, &new_name) {
                                Ok(0) => write("erro inesperado: usuario nao encontrado\n", 30),
                                Ok(_) => {
                                    write("seu usuario foi renomeado com sucesso\n", 30);
                                    // atualizar sessao para o novo nome
                                    session_user = Some(new_name);
                                }
                                Err(_) => write("erro ao renomear usuario (novo nome pode ja existir)\n", 30),
                            }
                        }
                        None => write("nenhum usuario logado: faca login para renomear\n", 30),
                    }
                }
            }

            "5" => { // quem sou eu
                match &session_user {
                    Some(u) => {
                        write(&format!("voce esta logado como: {}\n", u), 30);
                        if session_is_admin {
                            write("voce tem privilegios de administrador\n", 30);
                        }
                    }
                    None => write("nenhum usuario logado\n", 30),
                }
            }

            "6" => { // listar usuarios (apenas admin)
                if !session_is_admin {
                    write("opcao invalida, escolha um numero valido\n", 30);
                } else {
                    let mut stmt = conn.prepare("select username from users")?;
                    let mut rows = stmt.query([])?;
                    write("usuarios registrados:\n", 30);
                    while let Some(row) = rows.next()? {
                        let u: String = row.get(0)?;
                        write(&format!("- {}\n", u), 10);
                    }
                }
            }

            "q" => { // sair
                write("saindo...\n", 30);
                break;
            }

            _ => {
                write("opcao invalida, escolha uma opcao valida\n", 30);
            }
        }
    }

    Ok(())
}
