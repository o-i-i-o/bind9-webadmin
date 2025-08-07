use serde::Deserialize;
use std::fs;
use std::path::Path;
use log::warn;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub bind9: Bind9Config,
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Bind9Config {
    pub config_path: String,
    pub zones_path: String,
    pub service_name: String,
}

// 添加Default trait派生以修复serde(default)问题
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SessionConfig {
    pub secret: Option<String>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
    
    // 获取会话密钥，优先使用配置文件，其次使用环境变量，最后使用默认值
    pub fn get_session_secret(&self) -> String {
        // 1. 尝试从配置文件获取
        if let Some(secret) = &self.session.secret {
            if secret.len() >= 32 {
                return secret.clone();
            }
            warn!("Session secret in config file is too short (minimum 32 characters)");
        }
        
        // 2. 尝试从环境变量获取
        if let Ok(secret) = std::env::var("SESSION_SECRET") {
            if secret.len() >= 32 {
                return secret;
            }
            warn!("SESSION_SECRET environment variable is too short (minimum 32 characters)");
        }
        
        // 3. 使用默认密钥（仅用于开发环境）
        warn!("Using default session secret - THIS IS INSECURE FOR PRODUCTION!");
        "default-secret-key-12345678901234567890123456789012".to_string()
    }
}
