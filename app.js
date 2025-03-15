// server.js
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require('cors')

const app = express();
const PORT = 3000;
const JWT_SECRET = "your_jwt_secret"; // 生產環境請使用環境變數

const swaggerUi = require("swagger-ui-express");
const swaggerFile = require("./swagger_output.json"); // 剛剛輸出的 JSON

// 連接 MongoDB
mongoose
  .connect("mongodb://localhost:27017/auth_api")
  .then(() => {
    console.log("已連接到 MongoDB");
  })
  .catch((err) => {
    console.error("MongoDB 連接錯誤:", err);
  });

app.use(cors())

// 使用 JSON 解析，使開發人員更便利取用處理前端傳來的資料，
app.use(express.json()); // JSON 數據
app.use(express.urlencoded({ extended: true })); // 從 form 傳出的數據

// swagger 說明文件路由
app.use("/api-doc", swaggerUi.serve, swaggerUi.setup(swaggerFile));

// 註冊路由
app.post("/users", async (req, res) => {
  // #swagger.tags = ['Users']
  try {
    // step 1. 取出欄位
    const { nickname, password, email } = req.body.user;

    // step 2. 檢查必要欄位
    if (!nickname || !password || !email) {
      return res.status(400).json({ message: "所有欄位都是必填的" });
    }

    // step 3. 檢查重複的用戶名或電子郵件
    const db = mongoose.connection;
    const existingUser = await db.collection("users").findOne({
      $or: [{ nickname }, { email }],
    });

    if (existingUser) {
      return res.status(409).json({ message: "用戶名或電子郵件已存在" });
    }

    // step 3. 密碼加密
    const hashedPassword = await bcrypt.hash(password, 10);

    // step 4. 儲存用戶到 MongoDB
    try {
      await db.collection("users").insertOne({
        nickname,
        email,
        password: hashedPassword,
        createdAt: new Date().toISOString,
      });
    } catch (error) {
      console.error("用戶保存錯誤:", error);
      return res.status(422).json({ message: "註冊失敗" });
    }

    // step 6. 生成 JWT
    const currentTime = Math.floor(Date.now() / 1000); // 獲取當前 Unix 時間戳（秒）
    const token = jwt.sign(
      {
        nickname,
        email,
        iat: currentTime, // 發行時間（issued at）
        exp: currentTime + 60 * 60, // 1小時後過期
      },
      JWT_SECRET
    );

    // step 7. 返回成功訊息和令牌
    res.status(201).json({
      message: "註冊成功",
      token,
    });
  } catch (error) {
    console.error("註冊錯誤:", error);
    res.status(422).json({ message: "註冊失敗" });
  }
});

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

// 登入路由
app.post("/users/sign_in", async (req, res) => {
  // #swagger.tags = ['Users']
  try {
    const { nickname, password, email } = req.body.user;

    // 檢查必要欄位
    if ((!nickname && !email) || !password) {
      return res
        .status(400)
        .json({ message: "請提供使用者名稱/電子郵件和密碼" });
    }

    // 從 MongoDB 查找用戶
    const db = mongoose.connection;
    const user = await db.collection("users").findOne({
      $or: [{ nickname: nickname }, { email: email }],
    });

    // 檢查用戶是否存在
    if (!user) {
      return res.status(401).json({ message: "登入失敗" });
    }

    // 檢查密碼是否匹配
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "登入失敗" });
    }

    // 生成 JWT
    const currentTime = Math.floor(Date.now() / 1000);
    const token = jwt.sign(
      {
        id: user._id.toString(), // 添加用户ID以便在待辦事項API中使用
        nickname: user.nickname,
        email: user.email,
        iat: currentTime,
        exp: currentTime + 60 * 60, // 1小時後過期
      },
      JWT_SECRET
    );

    // 返回成功訊息和令牌
    res.status(200).json({
      message: "登入成功",
      token,
    });
  } catch (error) {
    console.error("登入錯誤:", error);
    res.status(401).json({ message: "登入失敗" });
  }
});

// 登出路由
app.delete("/users/sign_out", verifyToken, async (req, res) => {
  // #swagger.tags = ['Users']
  try {
    // 獲取令牌
    const token = req.headers.authorization.split(" ")[1];

    // 將令牌添加到黑名單
    const db = mongoose.connection;
    await db.collection("token_blacklist").insertOne({
      token,
      createdAt: new Date(),
      expiresAt: new Date(req.user.exp * 1000), // 設置與令牌相同的過期時間
    });

    // 創建TTL索引（如果不存在）確保自動清理過期令牌
    await db
      .collection("token_blacklist")
      .createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

    res.status(200).json({ message: "登出成功" });
  } catch (error) {
    console.error("登出錯誤:", error);
    res.status(401).json({ message: "登出失敗" });
  }
});

// 獲取MongoDB連接（簡化函數）
const getDB = async () => {
  return mongoose.connection.db;
};

// 1. 獲取待辦事項列表 - GET 方法
app.get("/todos", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;

    // 將字符串 ID 轉換為 ObjectId
    const objectId = new mongoose.Types.ObjectId(userId);

    // 查詢該用戶的所有待辦事項
    const todos = await db
      .collection("todos")
      .find({ userId: objectId })
      .sort({ createdAt: -1 })
      .toArray();

    // 將_id轉換為字符串以便於前端處理
    const formattedTodos = todos.map(todo => ({
      ...todo,
      _id: todo._id.toString()
    }));

    // 返回用戶的待辦事項列表
    return res.status(200).json(formattedTodos);
  } catch (error) {
    console.error("獲取待辦事項錯誤:", error);
    return res.status(500).json({ message: "伺服器錯誤", error: error.message });
  }
});

// 2. 新增待辦事項 - POST 方法
app.post("/todos", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;
    console.log("POST: 用戶ID:", userId);

    // 將字符串 ID 轉換為 ObjectId
    const userObjectId = new mongoose.Types.ObjectId(userId);
    console.log("POST: 用戶ObjectId:", userObjectId);

    console.log("POST: 原始請求體:", req.body);
    // 從請求格式中提取待辦事項數據
    const todoData = req.body.todo;
    console.log("POST: 提取的待辦事項數據:", todoData);

    // 檢查請求體格式，支持單個對象或對象數組
    const isBulkOperation = Array.isArray(todoData);
    const todoItems = isBulkOperation ? todoData : [todoData];

    if (!todoData || todoItems.length === 0) {
      return res.status(400).json({ message: "未提供待辦事項數據" });
    }

    // 創建待辦事項
    const createdTodos = [];

    for (const item of todoItems) {
      // 取出標題並驗證
      let title = item.title;
      title = title && title.trim() !== "" ? title.trim() : undefined;

      if (title === undefined) {
        continue; // 跳過無效數據
      }

      // 創建新的待辦事項
      const newTodo = {
        userId: userObjectId,
        title,
        completed: item.completed === true,
        createdAt: new Date().toISOString(),
      };
      console.log("POST: 準備插入的待辦事項:", newTodo);

      // 插入新待辦事項到資料庫
      const result = await db.collection("todos").insertOne(newTodo);
      console.log("POST: 插入結果:", result);

      // 添加到結果數組，包含MongoDB生成的ID
      createdTodos.push({
        ...newTodo,
        _id: result.insertedId.toString()
      });
    }

    if (createdTodos.length === 0) {
      return res.status(400).json({ message: "所有待辦事項標題無效" });
    }

    // 決定返回格式，單個或數組
    const responseData = isBulkOperation ? createdTodos : createdTodos[0];

    // 返回創建的待辦事項
    return res.status(201).json({ todo: responseData });
  } catch (error) {
    console.error("新增待辦事項錯誤:", error);
    if (
      (error.message && error.message.includes("authentication")) ||
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "未授權" });
    } else {
      return res.status(500).json({
        message: "伺服器錯誤",
        error: error.message
      });
    }
  }
});

// 3. 更新待辦事項 - PUT 方法
app.put("/todos/:id", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;
    console.log(`用戶ID: ${userId}`);

    // 從路徑參數獲取待辦事項ID
    const todoId = req.params.id;
    console.log(`待辦事項ID: ${todoId}`);

    // 驗證待辦事項ID格式
    if (!mongoose.Types.ObjectId.isValid(todoId)) {
      return res.status(400).json({ message: "無效的待辦事項ID格式" });
    }

    // 將待辦事項ID轉換為ObjectId
    const todoObjectId = new mongoose.Types.ObjectId(todoId);

    // 從請求格式中提取待辦事項數據
    console.log("PUT: 原始請求體:", req.body);
    const todoData = req.body.todo || {};
    console.log("更新數據:", todoData);

    // 將用戶ID轉換為ObjectId
    const userObjectId = new mongoose.Types.ObjectId(userId);
    console.log("PUT: 用戶ObjectId:", userObjectId);

    // 從請求體獲取更新的欄位
    const { title, completed } = todoData;

    // 準備更新數據
    const updateData = {};

    // 驗證：如果標題有提供且不為空，則加入更新數據
    if (title !== undefined) {
      updateData.title = title && title.trim() !== "" ? title.trim() : undefined;
      if (updateData.title === undefined) {
        delete updateData.title;
      }
    }

    // 如果完成狀態有提供，則加入更新數據
    if (completed !== undefined) {
      updateData.completed = !!completed; // 轉換為布林值
    }

    // 添加更新時間
    updateData.updatedAt = new Date().toISOString();

    console.log("PUT: 查詢條件:", { _id: todoObjectId, userId: userObjectId });
    console.log("PUT: 更新數據:", { $set: updateData });

    // 確保更新的是用戶自己的待辦事項
    const result = await db.collection("todos").findOneAndUpdate(
      { _id: todoObjectId, userId: userObjectId },
      { $set: updateData },
      { returnDocument: "after" } // 返回更新後的文檔
    );

    console.log("PUT: 更新操作結果:", result);

    // 如果找不到對應的待辦事項或不屬於當前用戶
    if (!result) {
      return res.status(404).json({ message: "待辦事項不存在或無權訪問" });
    }

    // 將_id轉換為字符串返回
    const updatedTodo = {
      ...result,
      _id: result._id.toString()
    };

    // 返回更新後的待辦事項
    return res.status(200).json({ todo: updatedTodo });
  } catch (error) {
    console.error("更新待辦事項錯誤:", error);
    return res.status(500).json({ message: "伺服器錯誤", error: error.message });
  }
});

// 4. 刪除待辦事項 - DELETE 方法
app.delete("/todos/:id", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;

    // 從路徑參數獲取待辦事項ID
    const todoId = req.params.id;

    // 驗證待辦事項ID格式
    if (!mongoose.Types.ObjectId.isValid(todoId)) {
      return res.status(400).json({ message: "無效的待辦事項ID格式" });
    }

    // 將待辦事項ID轉換為ObjectId
    const todoObjectId = new mongoose.Types.ObjectId(todoId);

    // 將用戶ID轉換為ObjectId
    const userObjectId = new mongoose.Types.ObjectId(userId);

    // 確保刪除的是用戶自己的待辦事項
    const result = await db.collection("todos").deleteOne({
      _id: todoObjectId,
      userId: userObjectId,
    });

    // 如果找不到對應的待辦事項或不屬於當前用戶
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "待辦事項不存在或無權訪問" });
    }

    // 返回刪除成功的訊息
    return res.status(200).json({ message: "已刪除" });
  } catch (error) {
    console.error("刪除待辦事項錯誤:", error);
    return res.status(500).json({ message: "伺服器錯誤", error: error.message });
  }
});

// 創建待辦事項集合索引
const createTodoIndexes = async () => {
  try {
    const db = await getDB();

    // 創建複合索引，加速查詢
    await db.collection("todos").createIndex({ userId: 1, completed: 1 });
    console.log("Todos indexes created successfully");
  } catch (error) {
    console.error("創建索引錯誤:", error);
  }
};

// 在資料庫連接成功後創建索引
mongoose.connection.once("open", async () => {
  // 創建待辦事項索引
  await createTodoIndexes();

  console.log("資料庫連接成功，索引已創建");
});

// 在 mongoose.connection.once('open', ...) 之後添加
mongoose.connection.on('error', (err) => {
  console.error('MongoDB 連接錯誤:', err);
});

// 定期檢查連接狀態
setInterval(() => {
  const state = mongoose.connection.readyState;
  const states = ['斷開連接', '已連接', '正在連接', '正在斷開連接'];
  console.log('MongoDB 連接狀態:', states[state]);
}, 60000); // 每分鐘檢查一次


// 啟動服務器
app.listen(PORT, () => {
  console.log(`服務器運行在端口 ${PORT}`);
});
