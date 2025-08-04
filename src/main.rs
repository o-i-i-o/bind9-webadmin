use actix_web::{App, HttpServer, middleware::Logger};
use env_logger::Env;
use std::sync::Mutex;

mod server;
mod bind9;
mod auth;
mod config;

use server::create_app_data;
use config::Config;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 初始化日志
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    // 加载配置
    let config = Config::from_file("config.toml").expect("Failed to load configuration");
    
    // 创建应用数据
    let app_data = create_app_data(config.clone());
    
    // 启动HTTP服务器
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_data.clone())
            .configure(server::config_routes)
    })
    .bind((config.server.address, config.server.port))?
    .run()
    .await
}
