use actix_web::{HttpServer, App};
use std::env;
use log::{info, error};
use tokio::runtime::Runtime;

// 声明内部模块
mod server;
mod config;
mod auth;
mod bind9;
mod i18n;

fn main() -> std::io::Result<()> {
    // 初始化日志
    env_logger::init();
    
    // 创建Tokio运行时
    let rt = Runtime::new()?;
    rt.block_on(async {
        // 读取配置文件
        let config_path = env::var("BIND9_WEBADMIN_CONFIG")
            .unwrap_or_else(|_| "config.toml".to_string());
        let config = match config::Config::from_file(&config_path).await {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to load configuration file: {}", e);
                std::process::exit(1);
            }
        };
        
        // 创建应用数据
        let app_data = server::create_app_data(config.clone()).await;
        
        // 确保BIND9区域目录存在
        let bind9_manager = app_data.bind9_manager.read().await;
        if let Err(e) = bind9_manager.ensure_zones_directory().await {
            error!("Failed to ensure zones directory exists: {}", e);
        }
        drop(bind9_manager);  // 提前释放读锁
        
        // 启动服务器
        let server_address = format!("{}:{}", config.server.host, config.server.port);
        info!("Starting BIND9 Web Admin on {}", server_address);
        
        HttpServer::new(move || {
            App::new()
                .app_data(app_data.clone())
                .configure(|cfg| server::config_routes(cfg, &app_data))
        })
        .bind(&server_address)?
        .run()
        .await
    })
}
