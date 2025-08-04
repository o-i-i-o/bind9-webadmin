use serde::Deserialize;
use std::fs;
use anyhow::{Result, Context};

// 服务器配置
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

// BIND9配置
#[derive(Debug, Deserialize, Clone)]
pub struct Bind9Config {
    pub service_name: String,
    pub binary_path: String,
    pub config_path: String,
    pub zones_dir: String,
}

// 认证配置
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password_hash: String,
}

// 应用配置
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub bind9: Bind9Config,
    pub auth: AuthConfig,
}

impl Config {
    // 从文件加载配置（使用toml crate）
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        
        let config = toml::from_str(&content)
            .context("Failed to parse config file")?;
        
        Ok(config)
    }
}
