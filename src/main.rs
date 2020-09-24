use actix_cors::Cors;
use actix_web::{web, get, middleware, Result, Responder, HttpResponse, HttpServer, App};
use actix_web::http::StatusCode;
use actix_session::{Session, CookieSession};
use serde::Deserialize;
use mysql::prelude::Queryable;
use chrono::{DateTime, NaiveDate, Utc};


#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate pwhash;

use regex::Regex;

lazy_static! {
    static ref db : mysqldata::MySQLData = mysqldata::MySQLData::init_connection(&String::from("rustsite"), &String::from("root"), &String::from("toor"));
}

// Module for MySQL
pub mod mysqldata {
    use mysql::{prelude::Queryable, params, chrono::NaiveDate, Row};
    use crate::{RegistrationForm, User};


    pub struct MySQLData {
        pub conn: mysql::Pool
    }



    impl MySQLData {
        //Return MySQLData object with conn field
        pub fn init_connection(database_name : &String, database_user : &String, database_pass : &String) -> MySQLData {
            let conn_str : String = format!("mysql://{user}:{pass}@localhost/{name}", user=database_user, pass=database_pass, name=database_name);
            let conn = mysql::Pool::new(conn_str);

            match conn {
                Ok(_) => {

                    println!("Connection to {} successful!", database_name);

                    MySQLData {
                        conn: conn.unwrap()
                    }
                },
                Err(e) => {
                    eprintln!("Connection to {} failed: {}", database_name, e.to_string());
                    std::process::exit(-1);
                }
            }
        }

        // Initialize all needed tables
        pub fn init_tables(&self) {
            let mut conn = self.conn.get_conn().unwrap();

            conn.query_drop(
                "CREATE TABLE IF NOT EXISTS users (
                    ID BIGINT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    email VARCHAR(256) NOT NULL,
                    birthdate DATETIME,
                    password VARCHAR(255) NOT NULL
                )"
            );

            println!("Tables initialized...");
        }

        pub fn add_user(&self, data: RegistrationForm) -> bool {
            let mut conn = self.conn.get_conn().unwrap();

            let date = NaiveDate::parse_from_str(&*data.birthdate, "%d-%m-%Y").unwrap();

            //let mut insert_id : i64 = -1;
            let execute_result = conn.exec_drop(r"
            INSERT INTO users (
                username, email, birthdate, password
            ) VALUES (
                :username, :email, :birthdate, :password
            )", params! {
                "username" => &data.username,
                "email" => data.email,
                "birthdate" => date.format("%Y-%m-%d").to_string(),
                "password" => pwhash::bcrypt::hash(data.password).unwrap()
            });

            //insert_id = self.conn.get_conn().unwrap().last_insert_id() as i64;


            match execute_result {
                Ok(_) => {
                    println!("User {} added!", data.username);
                    true
                }
                Err(e) => {
                    eprintln!("Failed to add user {}: {}", data.username, e.to_string());
                    false
                }
            }

            //insert_id
        }

        pub fn read_user_by_id(&self, id: u8) -> RegistrationForm {
            unimplemented!()
        }

        pub fn read_user_by_email(&self, email: String) -> User {
            let mut conn = self.conn.get_conn().unwrap();

            let stmt = conn.prep("SELECT id, username, email, birthdate, password FROM users WHERE email=:email").unwrap();
            let mut row : Row = conn.exec_first(&stmt, params! {
                "email" => email
            }).unwrap().unwrap();


            User {
                id: row.take("id").unwrap(),
                username: row.take("username").unwrap(),
                email: row.take("email").unwrap(),
                birthdate: row.take("birthdate").unwrap(),
                password_hash: row.take("password").unwrap(),
            }

        }
    }
}

#[derive(Deserialize)]
pub struct RegistrationForm {
    username: String,
    email: String,
    birthdate: String,
    password: String,
    rp_password: String
}
impl RegistrationForm {
    pub fn is_valid(&self) -> bool {
        if self.username.is_empty() ||
        self.email.is_empty() ||
        self.birthdate.is_empty() ||
        self.password.is_empty() ||
        self.rp_password.is_empty() {
            println!("User {} did not fill in all inputs!", self.username);
            return false
        }

        if self.password != self.rp_password {
            println!("User {} did not repeat the password correctly!", self.username);
            return false
        }

        let re_date = Regex::new(r"^\d{2}-\d{2}-\d{4}$").unwrap();
        if !re_date.is_match(&*&self.birthdate) {
            println!("{} for user {} is not a valid date", self.birthdate, self.username);
            return false
        }

        let re_email = Regex::new(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,3}").unwrap();
        if !re_email.is_match(&*&self.email) {
            println!("{} for user {} is not a valid mail-address", self.email, self.username);
            return false
        }

        true
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String
}

#[derive(Deserialize)]
pub struct User {
    id: u64,
    username: String,
    email: String,
    birthdate: chrono::NaiveDateTime,
    password_hash: String
}




//Function which gets executed with correct route
async fn register(form: web::Form<RegistrationForm>, session: Session) -> String {

    let registration_form = form.into_inner();

    if !registration_form.is_valid() {
        return String::from("error");
    }

    let add_result = db.add_user(registration_form);

    match add_result {
        true => String::from("ok"),
        false => String::from("error")
    }


}

async fn login(form: web::Form<LoginForm>, session: Session) -> String {

    let login_form = form.into_inner();

    let user : Option<User> = Some(db.read_user_by_email(login_form.email));

    match user {
        None => String::from("error"),
        Some(user) => {
            if pwhash::bcrypt::verify(login_form.password, &*user.password_hash) {
                session.set("user", user.id);
                String::from("ok")
            } else {
                String::from("error")
            }
        }
    }
}



#[actix_rt::main]
async fn main() -> std::io::Result<()> {

    db.init_tables();

    HttpServer::new(|| App::new()
        .wrap(
            Cors::new()
            .allowed_origin("http://rustsite.local")
            .finish()
        )
        .wrap(
            CookieSession::signed(&[0; 32])
            .secure(false)
        )
        .service(
            web::resource("/register").route(web::post().to(register))
        )
        .service(
            web::resource("/login").route(web::post().to(login))
        )
    )
    .bind("127.0.0.1:8088")?
    .run()
    .await
}
