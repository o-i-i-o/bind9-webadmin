use actix_web::{
    get, post, web, HttpResponse, Responder, Error as ActixError, HttpRequest,
};
use actix_session::{
    Session, SessionMiddleware, storage::CookieSessionStore
};
use actix_web_redis::RedisSessionStore;  // 使用正确的Redis会话存储
use actix_web::cookie::{Key, SameSite};
use actix_files::Files;
use serde::Deserialize;
use std::sync::Arc;
use tera::{Tera, Context};
use log::{error, info};
use std::time::Duration;
use parking_lot::RwLock;

// 导入本地模块
use super::{
    bind9::Bind9Manager, 
    auth::{self, UserStore, User}, 
    config::Config,
    i18n::{Language, self}
};

// 应用数据结构
#[derive(Clone)]
pub struct AppData {
    pub config: Config,
    pub tera: Tera,
    pub bind9_manager: Arc<RwLock<Bind9Manager>>,
    pub user_store: UserStore,
}

// 创建应用数据（异步版本）
pub async fn create_app_data(config: Config) -> web::Data<AppData> {
    // 初始化模板引擎（开发/生产环境不同配置）
    let tera = if cfg!(debug_assertions) {
        // 开发环境：实时重新加载模板
        match Tera::new("templates/**/*.html") {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to initialize Tera: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // 生产环境：预编译模板并禁用自动重新加载
        match Tera::new("templates/**/*.html") {
            Ok(mut t) => {
                t.auto_reload(false);
                t
            }
            Err(e) => {
                error!("Failed to initialize Tera: {}", e);
                std::process::exit(1);
            }
        }
    };
    
    // 创建BIND9管理器
    let bind9_manager = Arc::new(RwLock::new(Bind9Manager::new(config.clone())));
    
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

// 获取当前登录用户
async fn get_current_user(data: &web::Data<AppData>, session: &Session) -> Result<User, ActixError> {
    let username = session.get::<String>("username")?
        .ok_or_else(|| ActixError::from(actix_web::error::ErrorUnauthorized("Not authenticated")))?;
        
    data.user_store.get_by_username(&username)
        .ok_or_else(|| ActixError::from(actix_web::error::ErrorUnauthorized("User not found")))
}

// 认证中间件
pub async fn auth_middleware(
    session: Session,
    req: HttpRequest,
) -> Result<(), ActixError> {
    if !auth::is_authenticated(&session) {
        // 记录尝试访问的URL，登录后重定向回来
        let return_url = req.uri().to_string();
        session.insert("return_url", return_url)?;
        
        return Err(ActixError::from(
            actix_web::error::ErrorFound("/login")
        ));
    }
    Ok(())
}

// 管理员权限中间件
pub async fn admin_middleware(
    data: web::Data<AppData>,
    session: Session,
) -> Result<(), ActixError> {
    let user = get_current_user(&data, &session).await?;
    if !user.is_admin {
        return Err(ActixError::from(
            actix_web::error::ErrorForbidden("Admin privileges required")
        ));
    }
    Ok(())
}

// 路由配置
pub fn config_routes(cfg: &mut web::ServiceConfig, app_data: &web::Data<AppData>) {
    // 根据配置选择会话存储（Redis或Cookie）
    let session_middleware = if !app_data.config.redis.url.is_empty() {
        // 生产环境：使用Redis存储会话
        info!("Using Redis session store: {}", app_data.config.redis.url);
        SessionMiddleware::builder(
            RedisSessionStore::new(&app_data.config.redis.url)
                .expect("Failed to connect to Redis"),
            Key::from(&app_data.config.get_session_secret().into_bytes())
        )
        .cookie_secure(cfg!(not(debug_assertions))) // 生产环境启用HTTPS
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Lax)
        .session_ttl(Some(Duration::hours(app_data.config.get_session_ttl())))
        .build()
    } else {
        // 开发环境：使用Cookie存储会话
        info!("Using cookie session store (for development only)");
        SessionMiddleware::builder(
            CookieSessionStore::default(),
            Key::from(&app_data.config.get_session_secret().into_bytes())
        )
        .cookie_secure(false)  // 开发环境使用false
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Lax)
        .session_ttl(Some(Duration::hours(app_data.config.get_session_ttl())))
        .build()
    };
    
    cfg.service(
        web::scope("")
            .wrap(session_middleware)
            .service(index)
            .service(status)
            .service(login)
            .service(logout)
            .service(authenticate)
            // 添加区域创建路由
            .service(create_zone_form)
            .service(create_zone)
            .service(delete_zone)
            .service(check_config)
            .service(check_zone)
            .service(view_logs)
            // 需要认证的路由
            .service(
                web::scope("")
                    .wrap(web::middleware::from_fn(auth_middleware))
                    .service(config_view)
                    .service(config_save)
                    .service(zone_list)
                    .service(zone_view)
                    .service(zone_save)
                    .service(service_control)
                    // 需要管理员权限的路由
                    .service(
                        web::scope("")
                            .wrap(web::middleware::from_fn_with_state(
                                app_data.clone(), 
                                admin_middleware
                            ))
                            .service(users_list)
                            .service(user_create_form)
                            .service(user_create)
                            .service(user_edit_form)
                            .service(user_update)
                            .service(user_delete)
                    )
            )
            .service(Files::new("/static", "static").show_files_listing())
    );
}

// 首页
#[get("/")]
async fn index(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    // 复用上下文对象
    let mut context = Context::new();
    context.insert("title", t.get("home_title").unwrap());
    context.insert("t", &t);
    
    // 读取服务状态
    let bind9 = data.bind9_manager.read();
    let bind9_status = bind9.get_status().await.unwrap_or_default();
    context.insert("status", &bind9_status);
    drop(bind9);  // 提前释放读锁
    
    let rendered = data.tera.render("index.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 登录页面
#[get("/login")]
async fn login(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    if auth::is_authenticated(&session) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish());
    }
    
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut context = Context::new();
    context.insert("title", t.get("login").unwrap());
    context.insert("t", &t);
    
    let rendered = data.tera.render("login.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
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
    form: web::Form<LoginForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    // 异步验证凭据
    if auth::verify_credentials(&data.user_store, &form.username, &form.password).await {
        auth::set_authenticated(&session, &form.username)?;
        
        // 检查是否有需要返回的URL
        let return_url = session.get::<String>("return_url")?
            .unwrap_or_else(|| "/".to_string());
            
        // 清除return_url
        let _ = session.remove("return_url");
        
        Ok(HttpResponse::Found()
            .append_header(("Location", return_url))
            .finish())
    } else {
        let mut context = Context::new();
        context.insert("title", t.get("login").unwrap());
        context.insert("error", t.get("invalid_credentials").unwrap());
        context.insert("t", &t);
        
        let rendered = data.tera.render("login.html", &context)
            .map_err(|e| {
                error!("Template error: {}", e);
                ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
            })?;
        
        Ok(HttpResponse::Ok().body(rendered))
    }
}

// 登出
#[get("/logout")]
async fn logout(session: Session) -> impl Responder {
    // 清除会话数据
    session.clear();
    HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish()
}

// BIND9状态API
#[get("/status")]
async fn status(data: web::Data<AppData>, session: Session) -> Result<impl Responder, ActixError> {
    if !auth::is_authenticated(&session) {
        return Ok(HttpResponse::Unauthorized().body("Not authenticated"));
    }
    
    let bind9 = data.bind9_manager.read();
    let bind9_status = bind9.get_status().await.unwrap_or_default();
    Ok(HttpResponse::Ok().body(bind9_status))
}

// 查看配置文件
#[get("/config")]
async fn config_view(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    match bind9.read_config().await {
        Ok(content) => {
            let mut context = Context::new();
            context.insert("title", t.get("config_title").unwrap());
            context.insert("content", &content);
            context.insert("t", &t);
            context.insert("config_hint", t.get("config_hint").unwrap());
            
            let rendered = data.tera.render("config.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            error!("Failed to read config: {}", e);
            
            let mut context = Context::new();
            context.insert("title", t.get("config_title").unwrap());
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("config.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
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
    form: web::Form<ConfigForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut bind9 = data.bind9_manager.write();
    match bind9.write_config(&form.content).await {
        Ok(_) => {
            // 保存后检查配置
            let check_result = bind9.check_config().await;
            let message = match check_result {
                Ok(msg) => msg,
                Err(e) => format!("Saved but configuration error: {}", e),
            };
            
            // 重新加载服务
            let _ = bind9.reload().await;
            
            let mut context = Context::new();
            context.insert("title", t.get("config_title").unwrap());
            context.insert("content", &form.content);
            context.insert("message", &message);
            context.insert("t", &t);
            context.insert("config_hint", t.get("config_hint").unwrap());
            
            let rendered = data.tera.render("config.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            error!("Failed to save config: {}", e);
            
            let mut context = Context::new();
            context.insert("title", t.get("config_title").unwrap());
            context.insert("content", &form.content);
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("config.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

// 检查配置
#[get("/config/check")]
async fn check_config(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    let result = bind9.check_config().await;
    let content = bind9.read_config().await.unwrap_or_default();
    
    let mut context = Context::new();
    context.insert("title", t.get("config_title").unwrap());
    context.insert("content", &content);
    context.insert("t", &t);
    context.insert("config_hint", t.get("config_hint").unwrap());
    
    match result {
        Ok(msg) => {
            context.insert("message", &msg);
        }
        Err(e) => {
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
        }
    }
    
    let rendered = data.tera.render("config.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 查看日志
#[get("/logs")]
async fn view_logs(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    let logs = match bind9.get_logs().await {
        Ok(logs) => logs,
        Err(e) => {
            error!("Failed to get logs: {}", e);
            format!("{}: {}", t.get("error").unwrap(), e)
        }
    };
    
    let mut context = Context::new();
    context.insert("title", "BIND9 Logs");
    context.insert("logs", &logs);
    context.insert("t", &t);
    
    let rendered = data.tera.render("logs.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 区域列表
#[get("/zones")]
async fn zone_list(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    match bind9.list_zones().await {
        Ok(zones) => {
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("zones", &zones);
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            error!("Failed to list zones: {}", e);
            
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("error", &format!("{}: {}", t.get("zone_dir_not_exists").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

// 创建区域表单
#[get("/zones/create")]
async fn create_zone_form(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut context = Context::new();
    context.insert("title", t.get("create_zone").unwrap());
    context.insert("action", "/zones/create");
    context.insert("t", &t);
    
    let rendered = data.tera.render("zones/form.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 创建区域
#[derive(Deserialize)]
struct CreateZoneForm {
    zone_name: String,
    content: String,
}

#[post("/zones/create")]
async fn create_zone(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<CreateZoneForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut bind9 = data.bind9_manager.write();
    match bind9.create_zone(&form.zone_name, &form.content).await {
        Ok(_) => {
            // 创建成功后重新加载BIND9
            let _ = bind9.reload().await;
            
            Ok(HttpResponse::Found()
                .append_header(("Location", "/zones"))
                .finish())
        }
        Err(e) => {
            error!("Failed to create zone: {}", e);
            
            let mut context = Context::new();
            context.insert("title", t.get("create_zone").unwrap());
            context.insert("action", "/zones/create");
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("zone_name", &form.zone_name);
            context.insert("content", &form.content);
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/form.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

// 删除区域
#[get("/zones/{zone}/delete")]
async fn delete_zone(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let zone_name = path.into_inner();
    
    let mut bind9 = data.bind9_manager.write();
    match bind9.delete_zone(&zone_name).await {
        Ok(_) => {
            // 删除成功后重新加载BIND9
            let _ = bind9.reload().await;
            
            Ok(HttpResponse::Found()
                .append_header(("Location", "/zones"))
                .finish())
        }
        Err(e) => {
            error!("Failed to delete zone {}: {}", zone_name, e);
            
            let lang = Language::from_request(&req);
            let t = lang.get_translations();
            
            let bind9 = data.bind9_manager.read();
            let zones = bind9.list_zones().await.unwrap_or_default();
            
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("zones", &zones);
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}

// 检查区域文件
#[get("/zones/{zone}/check")]
async fn check_zone(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let zone_name = path.into_inner();
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    let result = bind9.check_zone(&zone_name).await;
    let content = bind9.read_zone(&zone_name).await.unwrap_or_default();
    
    let mut context = Context::new();
    context.insert("title", &format!("{}: {}", t.get("zones_title").unwrap(), zone_name));
    context.insert("zone", &zone_name);
    context.insert("content", &content);
    context.insert("t", &t);
    
    match result {
        Ok(msg) => {
            context.insert("message", &msg);
        }
        Err(e) => {
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
        }
    }
    
    let rendered = data.tera.render("zones/edit.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 查看区域文件
#[get("/zones/{zone}")]
async fn zone_view(
    data: web::Data<AppData>,
    session: Session,
    path: web::Path<String>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let zone = path.into_inner();
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let bind9 = data.bind9_manager.read();
    match bind9.read_zone(&zone).await {
        Ok(content) => {
            let mut context = Context::new();
            context.insert("title", &format!("{}: {}", t.get("zones_title").unwrap(), zone));
            context.insert("zone", &zone);
            context.insert("content", &content);
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/edit.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            error!("Failed to read zone {}: {}", zone, e);
            
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
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
    form: web::Form<ZoneForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let zone_name = path.into_inner();
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut bind9 = data.bind9_manager.write();
    match bind9.write_zone(&zone_name, &form.content).await {
        Ok(_) => {
            // 保存后检查区域文件
            let check_result = bind9.check_zone(&zone_name).await;
            
            // 重新加载服务
            let _ = bind9.reload().await;
            
            let mut context = Context::new();
            context.insert("title", &format!("{}: {}", t.get("zones_title").unwrap(), zone_name));
            context.insert("zone", &zone_name);
            context.insert("content", &form.content);
            context.insert("t", &t);
            
            match check_result {
                Ok(msg) => context.insert("message", &msg),
                Err(e) => context.insert("error", &format!("Saved but error: {}", e)),
            }
            
            let rendered = data.tera.render("zones/edit.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            error!("Failed to save zone {}: {}", zone_name, e);
            
            let mut context = Context::new();
            context.insert("title", &format!("{}: {}", t.get("zones_title").unwrap(), zone_name));
            context.insert("zone", &zone_name);
            context.insert("content", &form.content);
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/edit.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
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
    form: web::Form<ServiceControlForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut bind9 = data.bind9_manager.write();
    let result = match form.action.as_str() {
        "start" => bind9.start().await,
        "stop" => bind9.stop().await,
        "restart" => bind9.restart().await,
        "reload" => bind9.reload().await,
        _ => Err(anyhow::anyhow!("Unknown action: {}", form.action)),
    };
    
    let bind9_status = bind9.get_status().await.unwrap_or_default();
    
    let mut context = Context::new();
    context.insert("title", t.get("home_title").unwrap());
    context.insert("status", &bind9_status);
    context.insert("t", &t);
    
    match result {
        Ok(_) => {
            context.insert("message", &format!("{}: {}", t.get("success").unwrap(), form.action));
        }
        Err(e) => {
            error!("Service control error: {}", e);
            context.insert("error", &format!("{}: {}", t.get("error").unwrap(), e));
        }
    }
    
    let rendered = data.tera.render("index.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

// 用户管理相关处理函数
#[get("/users")]
async fn users_list(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let users = data.user_store.get_all();
    
    let mut context = Context::new();
    context.insert("title", t.get("users_title").unwrap());
    context.insert("users", &users);
    context.insert("t", &t);
    
    let rendered = data.tera.render("users/list.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
            ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
        })?;
    
    Ok(HttpResponse::Ok().body(rendered))
}

#[get("/users/create")]
async fn user_create_form(data: web::Data<AppData>, session: Session, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let mut context = Context::new();
    context.insert("title", t.get("create_user_title").unwrap());
    context.insert("action", "/users/create");
    context.insert("t", &t);
    
    let rendered = data.tera.render("users/form.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
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
    form: web::Form<CreateUserForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let new_user = auth::NewUser {
        username: form.username.clone(),
        password: form.password.clone(),
        is_admin: form.is_admin.is_some(),
    };
    
    match data.user_store.create(new_user).await {
        Ok(_) => {
            Ok(HttpResponse::Found()
                .append_header(("Location", "/users"))
                .finish())
        }
        Err(e) => {
            let mut context = Context::new();
            context.insert("title", t.get("create_user_title").unwrap());
            context.insert("action", "/users/create");
            context.insert("error", &e);
            context.insert("username", &form.username);
            context.insert("t", &t);
            
            let rendered = data.tera.render("users/form.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
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
    path: web::Path<String>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let user_id = path.into_inner();
    let user = data.user_store.get_by_id(&user_id)
        .ok_or_else(|| ActixError::from(actix_web::error::ErrorNotFound(t.get("user_not_found").unwrap())))?;
    
    let mut context = Context::new();
    context.insert("title", t.get("edit_user_title").unwrap());
    context.insert("action", &format!("/users/{}/update", user_id));
    context.insert("user", &user);
    context.insert("t", &t);
    
    let rendered = data.tera.render("users/form.html", &context)
        .map_err(|e| {
            error!("Template error: {}", e);
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
    form: web::Form<UpdateUserForm>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    let user_id = path.into_inner();
    let current_user = get_current_user(&data, &session).await?;
    
    // 不允许修改自己的管理员权限
    if current_user.id == user_id && form.is_admin.is_none() {
        return Ok(HttpResponse::BadRequest().body("Cannot remove admin status from yourself"));
    }
    
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
                .ok_or_else(|| ActixError::from(actix_web::error::ErrorNotFound(t.get("user_not_found").unwrap())))?;
            
            let mut context = Context::new();
            context.insert("title", t.get("edit_user_title").unwrap());
            context.insert("action", &format!("/users/{}/update", user_id));
            context.insert("error", &e);
            context.insert("user", &user);
            context.insert("t", &t);
            
            let rendered = data.tera.render("users/form.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
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
    path: web::Path<String>,
    req: HttpRequest
) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    // 获取当前用户
    let current_user = get_current_user(&data, &session).await?;
    
    // 不允许删除自己
    let user_id = path.into_inner();
    if current_user.id == user_id {
        let users = data.user_store.get_all();
        
        let mut context = Context::new();
        context.insert("title", t.get("users_title").unwrap());
        context.insert("users", &users);
        context.insert("error", t.get("cannot_delete_self").unwrap());
        context.insert("t", &t);
        
        let rendered = data.tera.render("users/list.html", &context)
            .map_err(|e| {
                error!("Template error: {}", e);
                ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
            })?;
        
        return Ok(HttpResponse::Ok().body(rendered));
    }
    
    match data.user_store.delete(&user_id) {
        Ok(_) => {
            Ok(HttpResponse::Found()
                .append_header(("Location", "/users"))
                .finish())
        }
        Err(e) => {
            let users = data.user_store.get_all();
            
            let mut context = Context::new();
            context.insert("title", t.get("users_title").unwrap());
            context.insert("users", &users);
            context.insert("error", &e);
            context.insert("t", &t);
            
            let rendered = data.tera.render("users/list.html", &context)
                .map_err(|e| {
                    error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}
