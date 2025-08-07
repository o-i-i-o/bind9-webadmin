// 在原有基础上添加以下修改
use super::i18n::{Language, self};

// 添加认证中间件
pub fn auth_middleware(
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

// 修改路由配置，添加认证中间件
pub fn config_routes(cfg: &mut web::ServiceConfig, app_data: &web::Data<AppData>) {
    cfg.service(
        web::scope("")
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::from(
                    &app_data.config.get_session_secret().into_bytes()
                )
            ))
            .service(index)
            .service(status)
            .service(login)
            .service(logout)
            .service(authenticate)
            // 需要认证的路由
            .service(
                web::scope("")
                    .wrap_fn(|req, srv| {
                        let session = req.get_session();
                        let result = auth_middleware(session.clone(), req.clone());
                        match result {
                            Ok(_) => srv.call(req),
                            Err(e) => async { Err(e) },
                        }
                    })
                    .service(config_view)
                    .service(config_save)
                    .service(zone_list)
                    .service(zone_view)
                    .service(zone_save)
                    .service(service_control)
                    .service(users_list)
                    .service(user_create_form)
                    .service(user_create)
                    .service(user_edit_form)
                    .service(user_update)
                    .service(user_delete)
            )
            .service(Files::new("/static", "static").show_files_listing())
    );
}

// 修改登录处理，支持重定向回原页面
#[post("/authenticate")]
async fn authenticate(
    data: web::Data<AppData>,
    session: Session,
    form: web::Form<LoginForm>
) -> Result<impl Responder, ActixError> {
    if auth::verify_credentials(&data.user_store, &form.username, &form.password) {
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
        let lang = Language::from_request(&data.request);
        let t = lang.get_translations();
        
        let mut context = Context::new();
        context.insert("title", t.get("login").unwrap());
        context.insert("error", t.get("invalid_credentials").unwrap());
        context.insert("t", &t);
        
        let rendered = data.tera.render("login.html", &context)
            .map_err(|e| {
                log::error!("Template error: {}", e);
                ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
            })?;
        
        Ok(HttpResponse::Ok().body(rendered))
    }
}

// 修改登出功能
#[get("/logout")]
async fn logout(session: Session) -> impl Responder {
    // 清除会话数据
    session.clear();
    HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish()
}

// 修改区域列表处理，处理目录不存在的情况
#[get("/zones")]
async fn zone_list(data: web::Data<AppData>, req: HttpRequest) -> Result<impl Responder, ActixError> {
    let lang = Language::from_request(&req);
    let t = lang.get_translations();
    
    match data.bind9_manager.lock().unwrap().list_zones() {
        Ok(zones) => {
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("zones", &zones);
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
        Err(e) => {
            log::error!("Failed to list zones: {}", e);
            
            let mut context = Context::new();
            context.insert("title", t.get("zones_title").unwrap());
            context.insert("error", &format!("{}: {}", t.get("zone_dir_not_exists").unwrap(), e));
            context.insert("t", &t);
            
            let rendered = data.tera.render("zones/list.html", &context)
                .map_err(|e| {
                    log::error!("Template error: {}", e);
                    ActixError::from(actix_web::error::ErrorInternalServerError("Template rendering error"))
                })?;
            
            Ok(HttpResponse::Ok().body(rendered))
        }
    }
}
