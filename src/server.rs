// 应用数据结构
#[derive(Clone)]
pub struct AppData {
    pub config: Config,
    pub tera: Tera,
    pub bind9_manager: Arc<Mutex<bind9::Bind9Manager>>,
    pub user_store: auth::UserStore,  // 新增用户存储
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
    
    // 初始化用户存储并添加默认管理员
    let user_store = auth::UserStore::new();
    user_store.init_default(
        &config.auth.username,
        &config.auth.password_hash
    );
    
    web::Data::new(AppData {
        config: config.clone(),
        tera,
        bind9_manager,
        user_store,  // 添加到应用数据
    })
}

// 添加用户管理相关路由
pub fn config_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::from(
                    &std::env::var("SESSION_SECRET")
                        .unwrap_or_else(|_| "default-secret-key-12345678901234567890123456789012".to_string())
                        .into_bytes()
                )
            ))
            // 现有路由...
            .service(users_list)
            .service(user_create_form)
            .service(user_create)
            .service(user_edit_form)
            .service(user_update)
            .service(user_delete)
            .service(Files::new("/static", "static").show_files_listing())
    );
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
    
    let update = auth::UpdateUser {
        password: form.password.clone(),
        is_admin: form.is_admin.map(|_| true).or_else(|| Some(false)),
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
async fn get_current_user(data: &web::Data<AppData>, session: &Session) -> Result<auth::User, ActixError> {
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

// 更新认证函数
pub fn is_authenticated(session: &Session) -> bool {
    session.get::<String>("username").is_ok()
}

pub fn set_authenticated(session: &Session, username: &str) -> Result<(), actix_session::SessionInsertError> {
    session.insert("username", username)
}
