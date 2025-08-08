use super::config::Config;
use std::path::Path;
use anyhow::{anyhow, Result};
use log::error;
use tokio::fs;
use tokio::process::Command;
use lru_cache::LruCache;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Bind9Manager {
    config_path: String,
    zones_path: String,
    service_name: String,
    // 缓存区域文件内容（key: 区域名，value: 内容），容量设为32
    zone_cache: Arc<RwLock<LruCache<String, String>>>,
}

impl Bind9Manager {
    pub fn new(config: Config) -> Self {
        Bind9Manager {
            config_path: config.bind9.config_path,
            zones_path: config.bind9.zones_path,
            service_name: config.bind9.service_name,
            zone_cache: Arc::new(RwLock::new(LruCache::new(32))), // 最多缓存32个区域文件
        }
    }
    
    // 检查区域目录是否存在，不存在则创建
    pub async fn ensure_zones_directory(&self) -> Result<()> {
        let zones_dir = Path::new(&self.zones_path);
        
        if !zones_dir.exists() {
            fs::create_dir_all(zones_dir)
                .await
                .map_err(|e| anyhow!("Failed to create zones directory: {}", e))?;
        }
        
        Ok(())
    }
    
    // 异步读取BIND9主配置
    pub async fn read_config(&self) -> Result<String> {
        fs::read_to_string(&self.config_path)
            .await
            .map_err(|e| anyhow!("Failed to read config file: {}", e))
    }
    
    // 异步写入BIND9主配置（先创建备份）
    pub async fn write_config(&self, content: &str) -> Result<()> {
        // 创建配置备份
        let backup_path = format!("{}.backup", self.config_path);
        fs::copy(&self.config_path, &backup_path)
            .await
            .map_err(|e| anyhow!("Failed to create config backup: {}", e))?;
        
        // 写入新配置
        fs::write(&self.config_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write config file: {}", e))
    }
    
    // 异步列出所有区域文件
    pub async fn list_zones(&self) -> Result<Vec<String>> {
        // 先尝试创建目录
        let _ = self.ensure_zones_directory().await;
        
        let zones_dir = Path::new(&self.zones_path);
        
        if !zones_dir.exists() {
            return Err(anyhow!("Zones directory does not exist: {}", self.zones_path));
        }
        
        let entries = fs::read_dir(zones_dir).await?;
        let mut zones = Vec::new();
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    zones.push(filename.to_string());
                }
            }
        }
        
        Ok(zones)
    }
    
    // 读取区域文件内容（优先从缓存获取）
    pub async fn read_zone(&self, zone_name: &str) -> Result<String> {
        // 尝试从缓存读取
        let mut cache = self.zone_cache.write();
        if let Some(content) = cache.get(zone_name) {
            return Ok(content.clone());
        }
        drop(cache); // 释放锁，避免阻塞其他操作
        
        // 缓存未命中，读取磁盘并更新缓存
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        if !zone_path.exists() {
            return Err(anyhow!("Zone file not found: {}", zone_name));
        }
        
        let content = fs::read_to_string(zone_path)
            .await
            .map_err(|e| anyhow!("Failed to read zone file: {}", e))?;
        
        // 更新缓存
        let mut cache = self.zone_cache.write();
        cache.insert(zone_name.to_string(), content.clone());
        
        Ok(content)
    }
    
    // 写入区域文件并更新缓存
    pub async fn write_zone(&self, zone_name: &str, content: &str) -> Result<()> {
        self.ensure_zones_directory().await?;
        
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        // 创建区域文件备份
        if zone_path.exists() {
            let backup_path = format!("{}.backup", zone_path.to_string_lossy());
            fs::copy(&zone_path, &backup_path)
                .await
                .map_err(|e| anyhow!("Failed to create zone backup: {}", e))?;
        }
        
        // 写入文件
        fs::write(zone_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write zone file: {}", e))?;
        
        // 更新缓存
        let mut cache = self.zone_cache.write();
        cache.insert(zone_name.to_string(), content.to_string());
        
        Ok(())
    }
    
    // 创建新区域文件
    pub async fn create_zone(&self, zone_name: &str, content: &str) -> Result<()> {
        // 确保目录存在
        self.ensure_zones_directory().await?;
        
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        if zone_path.exists() {
            return Err(anyhow!("Zone file already exists: {}", zone_name));
        }
        
        fs::write(zone_path, content)
            .await
            .map_err(|e| anyhow!("Failed to create zone file: {}", e))?;
        
        // 添加到缓存
        let mut cache = self.zone_cache.write();
        cache.insert(zone_name.to_string(), content.to_string());
        
        Ok(())
    }
    
    // 删除区域文件并从缓存移除
    pub async fn delete_zone(&self, zone_name: &str) -> Result<()> {
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        if !zone_path.exists() {
            return Err(anyhow!("Zone file not found: {}", zone_name));
        }
        
        fs::remove_file(zone_path)
            .await
            .map_err(|e| anyhow!("Failed to delete zone file: {}", e))?;
        
        // 从缓存移除
        let mut cache = self.zone_cache.write();
        cache.remove(zone_name);
        
        Ok(())
    }
    
    // 异步检查BIND9配置语法
    pub async fn check_config(&self) -> Result<String> {
        let output = Command::new("named-checkconf")
            .arg(&self.config_path)
            .output()
            .await?;
            
        if output.status.success() {
            Ok("Configuration is valid".to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Configuration error: {}", stderr))
        }
    }
    
    // 异步检查区域文件语法
    pub async fn check_zone(&self, zone_name: &str) -> Result<String> {
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        if !zone_path.exists() {
            return Err(anyhow!("Zone file not found: {}", zone_name));
        }
        
        let output = Command::new("named-checkzone")
            .arg(zone_name)
            .arg(zone_path)
            .output()
            .await?;
            
        if output.status.success() {
            Ok("Zone file is valid".to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Zone file error: {}", stderr))
        }
    }
    
    // 异步获取BIND9日志（最后100行）
    pub async fn get_logs(&self) -> Result<String> {
        let output = Command::new("tail")
            .arg("-n")
            .arg("100")
            .arg("/var/log/syslog")
            .output()
            .await?;
            
        if output.status.success() {
            let logs = String::from_utf8(output.stdout)
                .map_err(|e| anyhow!("Failed to parse logs: {}", e))?;
            
            // 过滤出BIND9相关日志
            let bind9_logs: String = logs.lines()
                .filter(|line| line.contains("named") || line.contains("bind9"))
                .map(|line| format!("{}\n", line))
                .collect();
                
            Ok(bind9_logs)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to read logs: {}", stderr))
        }
    }
    
    // 异步获取BIND9服务状态
    pub async fn get_status(&self) -> Result<String> {
        let output = Command::new("systemctl")
            .arg("status")
            .arg(&self.service_name)
            .output()
            .await?;
            
        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| anyhow!("Failed to parse status: {}", e))
        } else {
            // 服务未运行时也返回状态信息
            String::from_utf8(output.stderr)
                .map_err(|e| anyhow!("Failed to parse status: {}", e))
        }
    }
    
    // 异步启动BIND9服务
    pub async fn start(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("start")
            .arg(&self.service_name)
            .output()
            .await?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to start service: {}", stderr))
        }
    }
    
    // 异步停止BIND9服务
    pub async fn stop(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("stop")
            .arg(&self.service_name)
            .output()
            .await?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to stop service: {}", stderr))
        }
    }
    
    // 异步重启BIND9服务
    pub async fn restart(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg(&self.service_name)
            .output()
            .await?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to restart service: {}", stderr))
        }
    }
    
    // 异步重新加载BIND9配置
    pub async fn reload(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("reload")
            .arg(&self.service_name)
            .output()
            .await?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to reload service: {}", stderr))
        }
    }
}
