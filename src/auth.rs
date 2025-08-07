use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use actix_session::Session;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub password: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct UserStore {
    users: Arc<Mutex<HashMap<String, User>>>,
}

impl UserStore {
    pub fn new() -> Self {
        UserStore {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // 初始化默认管理员用户
    pub fn init_default(&self, default_username: &str, default_hash: &str) {
        let mut users = self.users.lock().unwrap();
        if !users.contains_key("1") {
            users.insert(
                "1".to_string(),
                User {
                    id: "1".to_string(),
                    username: default_username.to_string(),
                    password_hash: default_hash.to_string(),
                    is_admin: true,
                },
            );
        }
    }

    // 获取所有用户
    pub fn get_all(&self) -> Vec<User> {
        let users = self.users.lock().unwrap();
        users.values().cloned().collect()
    }

    // 通过ID获取用户
    pub fn get_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.lock().unwrap();
        users.get(id).cloned()
    }

    // 通过用户名获取用户
    pub fn get_by_username(&self, username: &str) -> Option<User> {
        let users = self.users.lock().unwrap();
        users.values()
            .find(|u| u.username == username)
            .cloned()
    }

    // 创建新用户
    pub fn create(&self, new_user: NewUser) -> Result<User, String> {
        let mut users = self.users.lock().unwrap();
        
        // 检查用户名是否已存在
        if users.values().any(|u| u.username == new_user.username) {
            return Err("Username already exists".to_string());
        }
        
        // 生成密码哈希
        let password_hash = hash(&new_user.password, DEFAULT_COST)
            .map_err(|e| format!("Failed to hash password: {}", e))?;
        
        // 生成新ID
        let id = (users.len() + 1).to_string();
        
        let user = User {
            id: id.clone(),
            username: new_user.username,
            password_hash,
            is_admin: new_user.is_admin,
        };
        
        users.insert(id, user.clone());
        Ok(user)
    }

    // 更新用户
    pub fn update(&self, id: &str, update: UpdateUser) -> Result<User, String> {
        let mut users = self.users.lock().unwrap();
        
        let user = users.get_mut(id)
            .ok_or_else(|| "User not found".to_string())?;
        
        // 更新密码（如果提供）
        if let Some(password) = &update.password {
            user.password_hash = hash(password, DEFAULT_COST)
                .map_err(|e| format!("Failed to hash password: {}", e))?;
        }
        
        // 更新管理员状态（如果提供）
        if let Some(is_admin) = update.is_admin {
            user.is_admin = is_admin;
        }
        
        Ok(user.clone())
    }

    // 删除用户
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut users = self.users.lock().unwrap();
        
        // 不能删除最后一个管理员
        let remaining_admins = users.values()
            .filter(|u| u.is_admin && u.id != id)
            .count();
            
        if remaining_admins == 0 {
            return Err("Cannot delete the last admin user".to_string());
        }
        
        if users.remove(id).is_none() {
            return Err("User not found".to_string());
        }
        
        Ok(())
    }
}

// 验证凭据
pub fn verify_credentials(user_store: &UserStore, username: &str, password: &str) -> bool {
    if let Some(user) = user_store.get_by_username(username) {
        return verify(password, &user.password_hash).unwrap_or(false);
    }
    false
}

// 生成密码哈希
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

// 检查用户是否已认证
pub fn is_authenticated(session: &Session) -> bool {
    session.get::<String>("username").is_ok()
}

// 设置用户认证状态
pub fn set_authenticated(session: &Session, username: &str) -> Result<(), actix_session::SessionInsertError> {
    session.insert("username", username)
}
