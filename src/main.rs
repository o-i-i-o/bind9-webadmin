use actix_web::{HttpServer, App};
use server::{create_app_data, config_routes};
use config::Config;
use std::env;
use log::{info, error};

// 声明内部模块，而不是引用外部crate
mod server;
mod config;
mod auth;
mod bind9;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 初始化日志
    env_logger::init();
    
    // 读取配置文件
    let config_path = env::var("BIND9_WEBADMIN_CONFIG")
        .unwrap_or_else(|_| "config.toml".to_string());
    let config = match Config::from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration file: {}", e);
            std::process::exit(1);
        }
    };
    
    // 创建应用数据
    let app_data = create_app_data(config.clone());
    
    // 启动服务器
    let server_address = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting BIND9 Web Admin on {}", server_address);
    
    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .configure(|cfg| config_routes(cfg, &app_data))
    })
    .bind(&server_address)?
    .run()
    .await
}
