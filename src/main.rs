use std::io;

fn main(){
    let users = ["admin"];      // users array
    //
    let passwd = ["admin 123"]; // passwords array
    //
    let mut login = String::new(); // input for the login
    //
    io::stdin().read_line(&mut login).expect("unexpected error");
    //
    let mut password = String::new(); // input for the password
    //
    io::stdin().read_line(&mut password).expect("unexpected error");


}