use std::fs;
use std::path::Path;  // 移除未使用的PathBuf
use duct::cmd;
use anyhow::{Result, Context};
use serde::Serialize;

use crate::config::Config;

// BIND9服务状态
#[derive(Debug, Serialize, Clone)]
pub struct Bind9Status {
    pub running: bool,
    pub version: Option<String>,
    pub last_started: Option<String>,
    pub config_path: String,
    pub zones_dir: String,
}

impl Default for Bind9Status {
    fn default() -> Self {
        Bind9Status {
            running: false,
            version: None,
            last_started: None,
            config_path: String::new(),
            zones_dir: String::new(),
        }
    }
}

// BIND9管理器
pub struct Bind9Manager {
    config: Config,
}

impl Bind9Manager {
    // 创建新的BIND9管理器
    pub fn new(config: Config) -> Self {
        Bind9Manager { config }
    }
    
    // 获取BIND9服务状态
    pub fn get_status(&mut self) -> Result<Bind9Status> {
        let status_output = cmd!("systemctl", "is-active", &self.config.bind9.service_name)
            .read()
            .context("Failed to check service status")?;
        
        let running = status_output.trim() == "active";
        
        let version_output = cmd!(&self.config.bind9.binary_path, "-v")
            .read()
            .ok();
        
        let version = version_output.as_ref()
            .and_then(|output| output.split_whitespace().nth(1).map(|s| s.to_string()));
        
        let last_started = cmd!("systemctl", "show", "--property=ActiveEnterTimestamp", &self.config.bind9.service_name)
            .read()
            .ok()
            .and_then(|output| {
                output.split('=').nth(1).map(|s| s.to_string())
            });
        
        Ok(Bind9Status {
            running,
            version,
            last_started,
            config_path: self.config.bind9.config_path.clone(),
            zones_dir: self.config.bind9.zones_dir.clone(),
        })
    }
    
    // 启动BIND9服务
    pub fn start(&mut self) -> Result<()> {
        cmd!("sudo", "systemctl", "start", &self.config.bind9.service_name)
            .run()
            .context("Failed to start BIND9 service")?;
        Ok(())
    }
    
    // 停止BIND9服务
    pub fn stop(&mut self) -> Result<()> {
        cmd!("sudo", "systemctl", "stop", &self.config.bind9.service_name)
            .run()
            .context("Failed to stop BIND9 service")?;
        Ok(())
    }
    
    // 重启BIND9服务
    pub fn restart(&mut self) -> Result<()> {
        cmd!("sudo", "systemctl", "restart", &self.config.bind9.service_name)
            .run()
            .context("Failed to restart BIND9 service")?;
        Ok(())
    }
    
    // 重新加载BIND9配置
    pub fn reload(&mut self) -> Result<()> {
        cmd!("sudo", "systemctl", "reload", &self.config.bind9.service_name)
            .run()
            .context("Failed to reload BIND9 service")?;
        Ok(())
    }
    
    // 读取主配置文件
    pub fn read_config(&mut self) -> Result<String> {
        let content = fs::read_to_string(&self.config.bind9.config_path)
            .with_context(|| format!("Failed to read config file: {}", self.config.bind9.config_path))?;
        Ok(content)
    }
    
    // 写入主配置文件
    pub fn write_config(&mut self, content: &str) -> Result<()> {
        fs::write(&self.config.bind9.config_path, content)
            .with_context(|| format!("Failed to write config file: {}", self.config.bind9.config_path))?;
        
        self.set_file_permissions(Path::new(&self.config.bind9.config_path))?;
        
        Ok(())
    }
    
    // 列出所有区域
    pub fn list_zones(&mut self) -> Result<Vec<String>> {
        let zones_dir = Path::new(&self.config.bind9.zones_dir);
        
        let entries = fs::read_dir(zones_dir)
            .with_context(|| format!("Failed to read zones directory: {:?}", zones_dir))?;
        
        let mut zones = Vec::new();
        
        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    zones.push(filename.to_string());
                }
            }
        }
        
        Ok(zones)
    }
    
    // 读取区域文件
    pub fn read_zone(&mut self, zone: &str) -> Result<String> {
        let zone_path = Path::new(&self.config.bind9.zones_dir).join(zone);
        
        let content = fs::read_to_string(&zone_path)
            .with_context(|| format!("Failed to read zone file: {:?}", zone_path))?;
        
        Ok(content)
    }
    
    // 写入区域文件
    pub fn write_zone(&mut self, zone: &str, content: &str) -> Result<()> {
        let zone_path = Path::new(&self.config.bind9.zones_dir).join(zone);
        
        fs::write(&zone_path, content)
            .with_context(|| format!("Failed to write zone file: {:?}", zone_path))?;
        
        self.set_file_permissions(&zone_path)?;
        
        Ok(())
    }
    
    // 设置文件权限
    fn set_file_permissions(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            let mut permissions = fs::metadata(path)
                .context("Failed to get file metadata")?
                .permissions();
            
            permissions.set_mode(0o644); // rw-r--r--
            
            fs::set_permissions(path, permissions)
                .context("Failed to set file permissions")?;
        }
        
        Ok(())
    }
}
