use serde::Deserialize;
use std::path::Path;
use log::{warn, error};
use tokio::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub bind9: Bind9Config,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub redis: RedisConfig,
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

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SessionConfig {
    pub secret: Option<String>,
    pub ttl_hours: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RedisConfig {
    pub url: String,
    pub database: Option<u8>,
}

impl Config {
    // 异步读取配置文件
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path).await?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
    
    // 获取会话密钥，确保长度至少为32字节
    pub fn get_session_secret(&self) -> String {
        // 1. 尝试从配置文件获取
        if let Some(secret) = &self.session.secret {
            if secret.len() >= 32 {
                return secret.clone();
            } else {
                error!("Session secret in config file is too short (has {} characters, needs at least 32)", secret.len());
            }
        }
        
        // 2. 尝试从环境变量获取
        if let Ok(secret) = std::env::var("SESSION_SECRET") {
            if secret.len() >= 32 {
                return secret;
            } else {
                error!("SESSION_SECRET environment variable is too short (has {} characters, needs at least 32)", secret.len());
            }
        }
        
        // 3. 生成一个随机的32字节密钥（用于开发环境）
        warn!("Generating random 32-character session secret - USE ONLY FOR DEVELOPMENT!");
        let secret = generate_random_secret(32);
        // 验证生成的密钥长度
        assert_eq!(secret.len(), 32, "Generated secret must be 32 characters long");
        secret
    }
    
    // 获取会话过期时间（小时）
    pub fn get_session_ttl(&self) -> u64 {
        self.session.ttl_hours.unwrap_or(24)
    }
}

// 生成指定长度的随机密钥
fn generate_random_secret(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789!@#$%^&*()_-+=[]{}|;:,.<>?";
    
    let secret: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    secret
}
