use actix_session::Session;
use bcrypt::{hash, verify, DEFAULT_COST};
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;
use log::warn;
use tokio::task;

#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateUser {
    pub password: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Clone)]
pub struct UserStore {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl UserStore {
    pub fn new() -> Self {
        UserStore {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    // 初始化默认管理员用户
    pub fn init_default(&self, username: &str, password_hash: &str) {
        let mut users = self.users.write();
        
        // 只有在没有用户时才添加默认用户
        if users.is_empty() {
            let user = User {
                id: Uuid::new_v4().to_string(),
                username: username.to_string(),
                password_hash: password_hash.to_string(),
                is_admin: true,
            };
            
            users.insert(user.id.clone(), user);
        }
    }
    
    // 获取所有用户
    pub fn get_all(&self) -> Vec<User> {
        let users = self.users.read();
        users.values().cloned().collect()
    }
    
    // 通过ID获取用户
    pub fn get_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.read();
        users.get(id).cloned()
    }
    
    // 通过用户名获取用户
    pub fn get_by_username(&self, username: &str) -> Option<User> {
        let users = self.users.read();
        users.values()
            .find(|u| u.username == username)
            .cloned()
    }
    
    // 异步创建新用户（密码哈希在单独线程中执行）
    pub async fn create(&self, new_user: NewUser) -> Result<(), String> {
        // 检查用户名是否已存在
        let users = self.users.read();
        if users.values().any(|u| u.username == new_user.username) {
            return Err("Username already exists".to_string());
        }
        drop(users);  // 提前释放读锁
        
        // 验证密码复杂度
        if new_user.password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }
        
        // 在单独的线程中执行密码哈希（CPU密集型操作）
        let password = new_user.password.clone();
        let password_hash = task::spawn_blocking(move || {
            hash(&password, DEFAULT_COST)
        }).await.map_err(|e| format!("Failed to hash password: {}", e))?
          .map_err(|e| format!("Failed to hash password: {}", e))?;
        
        // 创建用户
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: new_user.username,
            password_hash,
            is_admin: new_user.is_admin,
        };
        
        let mut users = self.users.write();
        users.insert(user.id.clone(), user);
        Ok(())
    }
    
    // 更新用户
    pub fn update(&self, id: &str, update: UpdateUser) -> Result<(), String> {
        let mut users = self.users.write();
        
        // 检查用户是否存在
        let user = users.get_mut(id)
            .ok_or_else(|| "User not found".to_string())?;
        
        // 更新密码（如果提供）
        if let Some(password) = &update.password {
            if !password.is_empty() {
                // 验证密码复杂度
                if password.len() < 8 {
                    return Err("Password must be at least 8 characters long".to_string());
                }
                
                // 同步哈希密码（在实际应用中可以改为异步）
                user.password_hash = hash(password, DEFAULT_COST)
                    .map_err(|e| format!("Failed to hash password: {}", e))?;
            }
        }
        
        // 更新管理员状态（如果提供）
        if let Some(is_admin) = update.is_admin {
            // 确保至少有一个管理员
            let admin_count = users.values().filter(|u| u.is_admin).count();
            if !is_admin && user.is_admin && admin_count <= 1 {
                return Err("Cannot remove the last admin user".to_string());
            }
            
            user.is_admin = is_admin;
        }
        
        Ok(())
    }
    
    // 删除用户
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut users = self.users.write();
        
        // 确保不是最后一个管理员
        if let Some(user) = users.get(id) {
            if user.is_admin {
                let admin_count = users.values().filter(|u| u.is_admin).count();
                if admin_count <= 1 {
                    return Err("Cannot delete the last admin user".to_string());
                }
            }
        } else {
            return Err("User not found".to_string());
        }
        
        users.remove(id);
        Ok(())
    }
}

// 异步验证凭据（在单独线程中执行）
pub async fn verify_credentials(user_store: &UserStore, username: &str, password: &str) -> bool {
    let user = match user_store.get_by_username(username) {
        Some(u) => u,
        None => return false,
    };
    
    // 在单独线程中执行密码验证（CPU密集型操作）
    let password = password.to_string();
    let password_hash = user.password_hash.clone();
    
    task::spawn_blocking(move || {
        verify(&password, &password_hash).unwrap_or(false)
    }).await.unwrap_or(false)
}

// 检查会话是否已认证
pub fn is_authenticated(session: &Session) -> bool {
    session.get::<String>("username").unwrap_or(None).is_some()
}

// 设置认证状态
pub fn set_authenticated(session: &Session, username: &str) -> Result<(), actix_web::error::Error> {
    if username.is_empty() {
        session.remove("username")?;
    } else {
        session.insert("username", username.to_string())?;
    }
    Ok(())
}
