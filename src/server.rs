use actix_web::{
    get, post, web, HttpResponse, Responder, Error as ActixError,
    // 移除未使用的dev::ServiceRequest导入
};
use actix_session::{
    Session, storage::CookieSessionStore, SessionMiddleware,
    cookie::Key  // 修正Key的导入路径
};
use actix_files::Files;
use serde::Deserialize;  // 移除未使用的Serialize
use std::sync::{Mutex, Arc};
use tera::{Tera, Context};
use anyhow::Result;

use crate::{bind9, auth, config::Config};

// 应用数据结构
#[derive(Clone)]
pub struct AppData {
    pub config: Config,
    pub tera: Tera,
    pub bind9_manager: Arc<Mutex<bind9::Bind9Manager>>,
}

// 创建应用数据
pub fn create_app_data(config: Config) -> web::Data<AppData> {
    let tera = match Tera::new("templates/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to initialize Tera: {}", e);
            std::process::exit(1);
        }
    };
    
    let bind9_manager = Arc::new(Mutex::new(bind9::Bind9Manager::new(config.clone())));
    
    web::Data::new(AppData {
        config: config.clone(),
        tera,
        bind9_manager,
    })
}

// 路由配置（移除不存在的zone_edit服务）
pub fn config_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::from(  // 使用正确导入的Key
                    std::env::var("SESSION_SECRET")
                        .unwrap_or_else(|_| "default-secret-key-12345".to_string())
                        .into_bytes()
                )
            ))
            .service(index)
            .service(status)
            .service(login)
            .service(logout)
            .service(authenticate)
            .service(config_view)
            .service(config_save)
            .service(zone_list)
            .service(zone_view)  // 保留zone_view替代zone_edit
            .service(zone_save)
            .service(service_control)
            .service(Files::new("/static", "static").show_files_listing())
    );
}

// 首页
#[get("/")]
async fn index(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let bind9_status = data.bind9_manager.lock().unwrap().get_status().unwrap_or_default();
    
    let mut context = Context::new();
    context.insert("title", "BIND9 Manager");
    context.insert("status", &bind9_status);
    
    let rendered = data.tera.render("index.html", &context)
        .map_err(|e| {
            log::error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 登录页面
#[get("/login")]
async fn login(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish());
    }
    
    let mut context = Context::new();
    context.insert("title", "Login - BIND9 Manager");
    
    let rendered = data.tera.render("login.html", &context)
        .map_err(|e| {
            log::error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 登录表单提交
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[post("/authenticate")]
async fn authenticate(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<LoginForm>
) -> Result<impl Responder, ActixError> {
    let config = &data.config;
    
    if auth::verify_credentials(config, &form.username, &form.password) {
        auth::set_authenticated(&session, true);
        Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish())
    } else {
        let mut context = Context::new();
        context.insert("title", "Login - BIND9 Manager");
        context.insert("error", "Invalid username or password");
        
        let rendered = data.tera.render("login.html", &context)
            .map_err(|e| {
                log::error!("Template error: {}", e);
                ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
            })?;
        
        Ok(HttpResponse::Ok().body(rendered))
    }
}

// 登出
#[get("/logout")]
async fn logout(session: Session) -> impl Responder {
    auth::set_authenticated(&session, false);
    HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish()
}

// BIND9状态
#[get("/status")]
async fn status(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let bind9_status = data.bind9_manager.lock().unwrap().get_status().unwrap_or_default();
    Ok(HttpResponse::Ok().json(bind9_status))
}

// 查看配置文件
#[get("/config")]
async fn config_view(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    match data.bind9_manager.lock().unwrap().read_config() {
        Ok(content) => {
            let mut context = Context::new();
            context.insert("title", "BIND9 Configuration");
            context.insert("content", &content);
            
            let rendered = data.tera.render("config.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            log::error!("Failed to read config: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to read configuration: {}", e)))
        }
    }
}

// 保存配置文件
#[derive(Deserialize)]
struct ConfigForm {
    content: String,
}

#[post("/config/save")]
async fn config_save(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<ConfigForm>
) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    match data.bind9_manager.lock().unwrap().write_config(&form.content) {
        Ok(_) => {
            data.bind9_manager.lock().unwrap().restart().ok();
            
            Ok(HttpResponse::Found()
                .append_header(("Location", "/config"))
                .finish())
        }
        Err(e) => {
            log::error!("Failed to save config: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to save configuration: {}", e)))
        }
    }
}

// 区域列表
#[get("/zones")]
async fn zone_list(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    match data.bind9_manager.lock().unwrap().list_zones() {
        Ok(zones) => {
            let mut context = Context::new();
            context.insert("title", "DNS Zones");
            context.insert("zones", &zones);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            log::error!("Failed to list zones: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to list zones: {}", e)))
        }
    }
}

// 查看区域文件
#[get("/zones/{zone}")]
async fn zone_view(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>
) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let zone = path.into_inner();
    
    match data.bind9_manager.lock().unwrap().read_zone(&zone) {
        Ok(content) => {
            let mut context = Context::new();
            context.insert("title", &format!("Zone: {}", zone));
            context.insert("zone", &zone);
            context.insert("content", &content);
            
            let rendered = data.tera.render("zones/edit.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            log::error!("Failed to read zone {}: {}", zone, e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to read zone: {}", e)))
        }
    }
}

// 保存区域文件
#[derive(Deserialize)]
struct ZoneForm {
    content: String,
}

#[post("/zones/{zone}/save")]
async fn zone_save(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>,
    form: web::Form<ZoneForm>
) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let zone_name = path.into_inner();
    
    match data.bind9_manager.lock().unwrap().write_zone(&zone_name, &form.content) {
        Ok(_) => {
            data.bind9_manager.lock().unwrap().reload().ok();
            
            Ok(HttpResponse::Found()
                .append_header(("Location", format!("/zones/{}", zone_name).as_str()))
                .finish())
        }
        Err(e) => {
            log::error!("Failed to save zone {}: {}", zone_name, e);
            Ok(HttpResponse::InternalServerError().body(format!("Failed to save zone: {}", e)))
        }
    }
}

// 服务控制
#[derive(Deserialize)]
struct ServiceControlForm {
    action: String,
}

#[post("/service/control")]
async fn service_control(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<ServiceControlForm>
) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let result = match form.action.as_str() {
        "start" => data.bind9_manager.lock().unwrap().start(),
        "stop" => data.bind9_manager.lock().unwrap().stop(),
        "restart" => data.bind9_manager.lock().unwrap().restart(),
        "reload" => data.bind9_manager.lock().unwrap().reload(),
        _ => Err(anyhow::anyhow!("Unknown action: {}", form.action)),
    };
    
    match result {
        Ok(_) => Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish()),
        Err(e) => {
            log::error!("Service control error: {}", e);
            Ok(HttpResponse::InternalServerError().body(format!("Service control failed: {}", e)))
        }
    }
}
