// auth.js - 跳转版，需要配合登录页使用

(function() {
  // ==================== 配置区域 ====================
  const LOGIN_PAGE = '/login.html';        // 登录页路径
  const API_BASE = 'http://39.107.248.76:8000'; // 后端API地址，改成您的服务器IP
  const TOKEN_KEY = 'access_token';
  const EXPIRY_KEY = 'token_expiry';
  // =================================================

  // 检查noscript（如果JS可用，隐藏noscript提示）
  const handleNoscript = () => {
    const noscriptDiv = document.getElementById('noscript-warning');
    if (noscriptDiv) {
      noscriptDiv.style.display = 'none';
    }
  };

  // 验证JWT令牌是否有效
  const validateToken = async (token) => {
    try {
      const response = await fetch(`${API_BASE}/api/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) return false;

      const data = await response.json();
      return data.valid === true;
    } catch (error) {
      console.error('Token验证失败:', error);
      return false;
    }
  };

  // 获取当前页面的完整URL（用于登录后跳回）
  const getCurrentPage = () => {
    return window.location.href;
  };

  // 主函数
  const initAuth = async () => {
    // 处理noscript
    handleNoscript();

    // 如果当前已经是登录页，不进行跳转
    if (window.location.pathname.endsWith('login.html')) {
      return;
    }

    // 检查本地存储的token
    const token = localStorage.getItem(TOKEN_KEY);
    const expiry = localStorage.getItem(EXPIRY_KEY);

    // 如果没有token或已过期，跳转到登录页
    if (!token || !expiry || Date.now() > parseInt(expiry)) {
      // 清除可能存在的无效数据
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(EXPIRY_KEY);

      // 跳转到登录页，带上当前页面作为redirect参数
      const redirect = encodeURIComponent(getCurrentPage());
      window.location.href = `${LOGIN_PAGE}?redirect=${redirect}`;
      return;
    }

    // 有token，验证有效性
    const isValid = await validateToken(token);

    if (!isValid) {
      // token无效，清除并跳转登录
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(EXPIRY_KEY);

      const redirect = encodeURIComponent(getCurrentPage());
      window.location.href = `${LOGIN_PAGE}?redirect=${redirect}`;
    }

    // token有效，继续加载页面
  };

  // 启动
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAuth);
  } else {
    initAuth();
  }
})();