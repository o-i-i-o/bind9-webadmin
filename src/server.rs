use actix_web::{
    get, post, web, HttpResponse, Responder, Error as ActixError,
};
use actix_session::{
    Session, storage::CookieSessionStore, SessionMiddleware
};
use actix_web::cookie::Key;
use actix_files::Files;
use serde::Deserialize;
use std::sync::{Mutex, Arc};
use tera::{Tera, Context};

// 导入本地模块（使用相对路径）
use super::{
    bind9::Bind9Manager, 
    auth::{self, UserStore, User}, 
    config::Config
};

// 应用数据结构
#[derive(Clone)]
pub struct AppData {
    pub config: Config,
    pub tera: Tera,
    pub bind9_manager: Arc<Mutex<Bind9Manager>>,
    pub user_store: UserStore,
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
    
    let bind9_manager = Arc::new(Mutex::new(Bind9Manager::new(config.clone())));
    
    // 初始化用户存储并添加默认管理员
    let user_store = UserStore::new();
    user_store.init_default(
        &config.auth.username,
        &config.auth.password_hash
    );
    
    web::Data::new(AppData {
        config: config.clone(),
        tera,
        bind9_manager,
        user_store,
    })
}

// 路由配置
pub fn config_routes(cfg: &mut web::ServiceConfig, app_data: &web::Data<AppData>) {
    cfg.service(
        web::scope("")
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                // 修复Key::from参数类型错误，添加引用
                Key::from(
                    &app_data.config.get_session_secret().into_bytes()
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
            .service(zone_view)
            .service(zone_save)
            .service(service_control)
            // 用户管理相关路由
            .service(users_list)
            .service(user_create_form)
            .service(user_create)
            .service(user_edit_form)
            .service(user_update)
            .service(user_delete)
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
    if auth::verify_credentials(&data.user_store, &form.username, &form.password) {
        auth::set_authenticated(&session, &form.username)?;
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
    let _ = auth::set_authenticated(&session, "");
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

// 用户管理相关处理函数
#[get("/users")]
async fn users_list(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    // 检查是否已认证且是管理员
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    let users = data.user_store.get_all();
    
    let mut context = Context::new();
    context.insert("title", "User Management");
    context.insert("users", &users);
    
    let rendered = data.tera.render("users/list.html", &context)
        .map_err(|e| {
            log::error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

#[get("/users/create")]
async fn user_create_form(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    // 检查权限
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    let mut context = Context::new();
    context.insert("title", "Create New User");
    context.insert("action", "/users/create");
    
    let rendered = data.tera.render("users/form.html", &context)
        .map_err(|e| {
            log::error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

#[derive(Deserialize)]
struct CreateUserForm {
    username: String,
    password: String,
    is_admin: Option<String>,  // 复选框会发送"on"或不发送
}

#[post("/users/create")]
async fn user_create(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<CreateUserForm>
) -> Result<impl Responder, ActixError> {
    // 检查权限
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    let new_user = auth::NewUser {
        username: form.username.clone(),
        password: form.password.clone(),
        is_admin: form.is_admin.is_some(),
    };
    
    match data.user_store.create(new_user) {
        Ok(_) => {
            Ok(HttpResponse::Found()
                .append_header(("Location", "/users"))
                .finish())
        }
        Err(e) => {
            let mut context = Context::new();
            context.insert("title", "Create New User");
            context.insert("action", "/users/create");
            context.insert("error", &e);
            context.insert("username", &form.username);
            
            let rendered = data.tera.render("users/form.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

#[get("/users/{id}/edit")]
async fn user_edit_form(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>
) -> Result<impl Responder, ActixError> {
    // 检查权限
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    let user_id = path.into_inner();
    let user = data.user_store.get_by_id(&user_id)
        .ok_or_else(|| ActixError::from(actix_web::error::ErrorNotFound("User not found")))?;
    
    let mut context = Context::new();
    context.insert("title", "Edit User");
    context.insert("action", &format!("/users/{}/update", user_id));
    context.insert("user", &user);
    
    let rendered = data.tera.render("users/form.html", &context)
        .map_err(|e| {
            log::error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

#[derive(Deserialize)]
struct UpdateUserForm {
    password: Option<String>,
    is_admin: Option<String>,
}

#[post("/users/{id}/update")]
async fn user_update(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>,
    form: web::Form<UpdateUserForm>
) -> Result<impl Responder, ActixError> {
    // 检查权限
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    let user_id = path.into_inner();
    
    // 不允许修改自己的管理员权限
    if current_user.id == user_id && form.is_admin.is_none() {
        return Ok(HttpResponse::BadRequest().body("Cannot remove admin status from yourself"));
    }
    
    // 修复移动语义错误，使用clone()
    let update = auth::UpdateUser {
        password: form.password.clone(),
        is_admin: form.is_admin.clone().map(|_| true).or_else(|| Some(false)),
    };
    
    match data.user_store.update(&user_id, update) {
        Ok(_) => {
            Ok(HttpResponse::Found()
                .append_header(("Location", "/users"))
                .finish())
        }
        Err(e) => {
            let user = data.user_store.get_by_id(&user_id)
                .ok_or_else(|| ActixError::from(actix_web::error::ErrorNotFound("User not found")))?;
            
            let mut context = Context::new();
            context.insert("title", "Edit User");
            context.insert("action", &format!("/users/{}/update", user_id));
            context.insert("error", &e);
            context.insert("user", &user);
            
            let rendered = data.tera.render("users/form.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

#[get("/users/{id}/delete")]
async fn user_delete(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>
) -> Result<impl Responder, ActixError> {
    // 检查权限
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish());
    }
    
    let current_user = get_current_user(&data, &session).await?;
    if !current_user.is_admin {
        return Ok(HttpResponse::Forbidden().body("Access denied: Admin privileges required"));
    }
    
    // 不允许删除自己
    let user_id = path.into_inner();
    if current_user.id == user_id {
        return Ok(HttpResponse::BadRequest().body("Cannot delete your own account"));
    }
    
    match data.user_store.delete(&user_id) {
        Ok(_) => {
            Ok(HttpResponse::Found()
                .append_header(("Location", "/users"))
                .finish())
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest().body(e))
        }
    }
}

// 辅助函数：获取当前登录用户
async fn get_current_user(data: &web::Data<AppData>, session: &Session) -> Result<User, ActixError> {
    let username = session.get::<String>("username")
        .map_err(|e| {
            log::error!("Session error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Session error"))
        })?
        .ok_or_else(|| {
            ActixError::from(actix_web::error::ErrorUnauthorized("Not authenticated"))
        })?;
    
    data.user_store.get_by_username(&username)
        .ok_or_else(|| {
            ActixError::from(actix_web::error::ErrorUnauthorized("User not found"))
        })
}
