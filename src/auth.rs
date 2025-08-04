use actix_session::Session;
use bcrypt::{DEFAULT_COST, hash, verify};

use crate::config::Config;

// 会话密钥
const AUTHENTICATED_KEY: &str = "authenticated";

// 检查用户是否已认证
pub fn is_authenticated(session: &Session) -> bool {
    session.get::<bool>(AUTHENTICATED_KEY).unwrap_or(false)
}

// 设置用户认证状态
pub fn set_authenticated(session: &Session, authenticated: bool) {
    let _ = session.insert(AUTHENTICATED_KEY, authenticated);
}

// 验证用户凭据
pub fn verify_credentials(config: &Config, username: &str, password: &str) -> bool {
    // 检查用户名是否匹配
    if username != config.auth.username {
        return false;
    }
    
    // 验证密码哈希
    match verify(password, &config.auth.password_hash) {
        Ok(result) => result,
        Err(_) => false,
    }
}

// 生成密码哈希（用于初始化设置）
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}
