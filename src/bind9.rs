use super::config::Config;
use std::fs;
use std::path::Path;
use std::process::Command;
use anyhow::{anyhow, Result};
use log::error;

#[derive(Debug, Clone)]
pub struct Bind9Manager {
    config_path: String,
    zones_path: String,
    service_name: String,
}

impl Bind9Manager {
    pub fn new(config: Config) -> Self {
        Bind9Manager {
            config_path: config.bind9.config_path,
            zones_path: config.bind9.zones_path,
            service_name: config.bind9.service_name,
        }
    }
    
    // 读取BIND9主配置文件
    pub fn read_config(&self) -> Result<String> {
        fs::read_to_string(&self.config_path)
            .map_err(|e| anyhow!("Failed to read config file: {}", e))
    }
    
    // 写入BIND9主配置文件
    pub fn write_config(&self, content: &str) -> Result<()> {
        fs::write(&self.config_path, content)
            .map_err(|e| anyhow!("Failed to write config file: {}", e))
    }
    
    // 获取区域文件列表
    pub fn list_zones(&self) -> Result<Vec<String>> {
        let zones_dir = Path::new(&self.zones_path);
        
        if !zones_dir.exists() {
            return Err(anyhow!("Zones directory does not exist: {}", self.zones_path));
        }
        
        let entries = fs::read_dir(zones_dir)?;
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
    
    // 读取区域文件内容
    pub fn read_zone(&self, zone_name: &str) -> Result<String> {
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        if !zone_path.exists() {
            return Err(anyhow!("Zone file not found: {}", zone_name));
        }
        
        fs::read_to_string(zone_path)
            .map_err(|e| anyhow!("Failed to read zone file: {}", e))
    }
    
    // 写入区域文件
    pub fn write_zone(&self, zone_name: &str, content: &str) -> Result<()> {
        let zone_path = Path::new(&self.zones_path).join(zone_name);
        
        fs::write(zone_path, content)
            .map_err(|e| anyhow!("Failed to write zone file: {}", e))
    }
    
    // 获取BIND9服务状态
    pub fn get_status(&self) -> Result<String> {
        let output = Command::new("systemctl")
            .arg("status")
            .arg(&self.service_name)
            .output()?;
            
        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| anyhow!("Failed to parse status output: {}", e))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("Failed to get status: {}", stderr))
        }
    }
    
    // 启动BIND9服务
    pub fn start(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("start")
            .arg(&self.service_name)
            .output()?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to start service: {}", stderr);
            Err(anyhow!("Failed to start service: {}", stderr))
        }
    }
    
    // 停止BIND9服务
    pub fn stop(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("stop")
            .arg(&self.service_name)
            .output()?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to stop service: {}", stderr);
            Err(anyhow!("Failed to stop service: {}", stderr))
        }
    }
    
    // 重启BIND9服务
    pub fn restart(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg(&self.service_name)
            .output()?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to restart service: {}", stderr);
            Err(anyhow!("Failed to restart service: {}", stderr))
        }
    }
    
    // 重新加载BIND9配置
    pub fn reload(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("reload")
            .arg(&self.service_name)
            .output()?;
            
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to reload service: {}", stderr);
            Err(anyhow!("Failed to reload service: {}", stderr))
        }
    }
}
