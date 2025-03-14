// JWT 驗證中間件
const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "未提供 JWT 令牌" });
  }

  try {
    // 檢查令牌是否被列入黑名單
    const db = mongoose.connection;
    const blacklistedToken = await db
      .collection("token_blacklist")
      .findOne({ token });

    if (blacklistedToken) {
      return res.status(401).json({ message: "登出狀態，請重新登入" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "JWT 令牌無效" });
  }
};

// 受保護的路由示例
app.get("/todos", verifyToken, (req, res) => {
    // #swagger.tags = ['Todos']

    // 請從這裡開始 使用 nodejs + mongoose 語法，幫我接入剛剛你提供的  TodoList MongoDB 最小可行架構
    // 記得力求最小可行、可讀友善、維護友善為前提
});