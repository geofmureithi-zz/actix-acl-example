#[macro_use]
extern crate actix_web;
use actix_web::{
    dev::Payload, error::ErrorUnauthorized, web, App, Error, FromRequest,
    HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix::prelude::*;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, pin::Pin, sync::RwLock};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Sessions {
    map: HashMap<String, User>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct Login {
    id: String,
    username: String,
    scope: Scope
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Scope {
    Guest,
    User,
    Admin
}

impl Default for Scope {
    fn default() -> Self { Scope::Guest }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    first_name: Option<String>,
    last_name: Option<String>,
    authorities: Scope,
}

impl FromRequest for User {
    type Config = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<User, Error>>>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        let fut = Identity::from_request(req, pl);
        let sessions: Option<&web::Data<RwLock<Sessions>>> = req.app_data();
        if sessions.is_none() {
            warn!("sessions is empty(none)!");
            return Box::pin(async { Err(ErrorUnauthorized("unauthorized")) });
        }
        let sessions = sessions.unwrap().clone();
        Box::pin(async move {
            if let Some(identity) = fut.await?.identity() {
                if let Some(user) = sessions
                    .read()
                    .unwrap()
                    .map
                    .get(&identity)
                    .map(|x| x.clone())
                {
                    return Ok(user);
                }
            };

            Err(ErrorUnauthorized("unauthorized"))
        })
    }
}

#[get("/admin")]
async fn admin(user: User) -> impl Responder {
    if user.authorities != Scope::Admin {
        return HttpResponse::Unauthorized().finish()
    }
    HttpResponse::Ok().body("You are an admin")
}


#[get("/account")]
async fn account(user: User) -> impl Responder {
    web::Json(user)
}

#[post("/login")]
async fn login(login: web::Json<Login>, sessions: web::Data<RwLock<Sessions>>, identity: Identity) -> impl Responder {
    let id = login.id.to_string();
    let scope = &login.scope;
    //let user = fetch_user(login).await // from db?
    identity.remember(id.clone());
    let user = User {
        id: id.clone(),
        last_name: Some(String::from("Doe")),
        first_name: Some(String::from("John")),
        authorities: scope.clone(),
    };
    sessions
        .write()
        .unwrap()
        .map
        .insert(id, user.clone());
    info!("login user: {:?}", user);
    HttpResponse::Ok().json(user)
}

#[post("/logout")]
async fn logout(
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
) -> impl Responder {
    if let Some(id) = identity.identity() {
        identity.forget();
        if let Some(user) = sessions.write().unwrap().map.remove(&id) {
            warn!("logout user: {:?}", user);
        }
    }
    HttpResponse::Unauthorized().finish()
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let sessions = web::Data::new(RwLock::new(Sessions {
        map: HashMap::new(),
    }));

    HttpServer::new(move || {
        App::new()
            .app_data(sessions.clone())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("test")
                    .secure(false),
            ))
            .service(account)
            .service(login)
            .service(logout)
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}