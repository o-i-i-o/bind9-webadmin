use actix_web::HttpRequest;
use std::collections::HashMap;
use lazy_static::lazy_static;

// 定义支持的语言
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Chinese,
    English,
}

impl Language {
    // 从请求头获取语言设置
    pub fn from_request(req: &HttpRequest) -> Self {
        if let Some(lang_header) = req.headers().get("Accept-Language") {
            if let Ok(lang_str) = lang_header.to_str() {
                // 简单匹配中文
                if lang_str.contains("zh") || lang_str.contains("cn") {
                    return Language::Chinese;
                }
            }
        }
        // 默认英文
        Language::English
    }
    
    // 获取对应的翻译映射
    pub fn get_translations(&self) -> &'static HashMap<&'static str, &'static str> {
        match self {
            Language::Chinese => &CHINESE_TRANSLATIONS,
            Language::English => &ENGLISH_TRANSLATIONS,
        }
    }
}

// 英文翻译
lazy_static! {
    static ref ENGLISH_TRANSLATIONS: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        // 通用翻译
        map.insert("title", "BIND9 Manager");
        map.insert("login", "Login");
        map.insert("logout", "Logout");
        map.insert("username", "Username");
        map.insert("password", "Password");
        map.insert("submit", "Submit");
        map.insert("cancel", "Cancel");
        map.insert("save", "Save");
        map.insert("error", "Error");
        map.insert("success", "Success");
        
        // 页面标题
        map.insert("home_title", "Home");
        map.insert("config_title", "BIND9 Configuration");
        map.insert("zones_title", "DNS Zones");
        map.insert("users_title", "User Management");
        map.insert("create_user_title", "Create New User");
        map.insert("edit_user_title", "Edit User");
        
        // 错误信息
        map.insert("not_authenticated", "Not authenticated");
        map.insert("invalid_credentials", "Invalid username or password");
        map.insert("access_denied", "Access denied: Admin privileges required");
        map.insert("user_not_found", "User not found");
        map.insert("cannot_delete_self", "Cannot delete your own account");
        map.insert("cannot_remove_last_admin", "Cannot delete the last admin user");
        map.insert("username_exists", "Username already exists");
        map.insert("zone_dir_not_exists", "Zones directory does not exist");
        
        // 功能文本
        map.insert("service_status", "BIND9 Service Status");
        map.insert("service_control", "Service Control");
        map.insert("start", "Start");
        map.insert("stop", "Stop");
        map.insert("restart", "Restart");
        map.insert("reload", "Reload");
        map.insert("zone_name", "Zone Name");
        map.insert("actions", "Actions");
        map.insert("edit", "Edit");
        map.insert("delete", "Delete");
        map.insert("create_new_user", "Create New User");
        map.insert("admin", "Administrator");
        map.insert("admin_desc", "Admin users have full access to all features");
        map.insert("password_placeholder", "Leave empty to keep current password");
        map.insert("new_password_placeholder", "Enter password");
        map.insert("config_hint", "Zone files can be managed at: http://192.168.6.253:8080/zones");
        
        map
    };
    
    // 中文翻译
    static ref CHINESE_TRANSLATIONS: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        // 通用翻译
        map.insert("title", "BIND9 管理器");
        map.insert("login", "登录");
        map.insert("logout", "退出");
        map.insert("username", "用户名");
        map.insert("password", "密码");
        map.insert("submit", "提交");
        map.insert("cancel", "取消");
        map.insert("save", "保存");
        map.insert("error", "错误");
        map.insert("success", "成功");
        
        // 页面标题
        map.insert("home_title", "首页");
        map.insert("config_title", "BIND9 配置");
        map.insert("zones_title", "DNS 区域");
        map.insert("users_title", "用户管理");
        map.insert("create_user_title", "创建新用户");
        map.insert("edit_user_title", "编辑用户");
        
        // 错误信息
        map.insert("not_authenticated", "未认证");
        map.insert("invalid_credentials", "用户名或密码无效");
        map.insert("access_denied", "访问被拒绝：需要管理员权限");
        map.insert("user_not_found", "用户不存在");
        map.insert("cannot_delete_self", "不能删除自己的账户");
        map.insert("cannot_remove_last_admin", "不能删除最后一个管理员");
        map.insert("username_exists", "用户名已存在");
        map.insert("zone_dir_not_exists", "区域文件目录不存在");
        
        // 功能文本
        map.insert("service_status", "BIND9 服务状态");
        map.insert("service_control", "服务控制");
        map.insert("start", "启动");
        map.insert("stop", "停止");
        map.insert("restart", "重启");
        map.insert("reload", "重新加载");
        map.insert("zone_name", "区域名称");
        map.insert("actions", "操作");
        map.insert("edit", "编辑");
        map.insert("delete", "删除");
        map.insert("create_new_user", "创建新用户");
        map.insert("admin", "管理员");
        map.insert("admin_desc", "管理员用户拥有所有功能的完全访问权限");
        map.insert("password_placeholder", "留空则保持当前密码");
        map.insert("new_password_placeholder", "输入密码");
        map.insert("config_hint", "区域文件可在以下地址管理：http://192.168.6.253:8080/zones");
        
        map
    };
}
