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
    const { username, password, email } = req.body;

    // step 2. 檢查必要欄位
    if (!username || !password || !email) {
      return res.status(400).json({ message: "所有欄位都是必填的" });
    }

    // step 3. 檢查重複的用戶名或電子郵件
    const db = mongoose.connection;
    const existingUser = await db.collection("users").findOne({
      $or: [{ username }, { email }],
    });

    if (existingUser) {
      return res.status(409).json({ message: "用戶名或電子郵件已存在" });
    }

    // step 3. 密碼加密
    const hashedPassword = await bcrypt.hash(password, 10);

    // step 4. 儲存用戶到 MongoDB
    try {
      await db.collection("users").insertOne({
        username,
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
        username,
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
    const { username, password, email } = req.body;

    // 檢查必要欄位
    if ((!username && !email) || !password) {
      return res
        .status(400)
        .json({ message: "請提供使用者名稱/電子郵件和密碼" });
    }

    // 從 MongoDB 查找用戶
    const db = mongoose.connection;
    const user = await db.collection("users").findOne({
      $or: [{ username: username }, { email: email }],
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
        username: user.username,
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

// 初始化 ID 映射集合
async function initializeIdMapping() {
  try {
    const db = await getDB();

    // 檢查計數器集合是否存在並創建計數器
    const counter = await db
      .collection("counters")
      .findOne({ _id: "numericId" });
    if (!counter) {
      await db.collection("counters").insertOne({ _id: "numericId", seq: 0 });
      console.log("已創建數字 ID 計數器");
    }

    // 檢查是否已經存在映射集合
    const collections = await db
      .listCollections({ name: "id_mappings" })
      .toArray();
    if (collections.length === 0) {
      // 創建 ID 映射集合
      await db.createCollection("id_mappings");
      console.log("已創建 ID 映射集合");

      // 為每個現有的待辦事項創建映射
      const todos = await db.collection("todos").find({}).toArray();
      console.log(`找到 ${todos.length} 個現有待辦事項進行 ID 映射`);

      for (const todo of todos) {
        const numericId = await getNextId();
        await db.collection("id_mappings").insertOne({
          objectId: todo._id,
          numericId: numericId,
          collection: "todos",
        });
        console.log(`已映射: ${todo._id} -> ${numericId}`);
      }

      // 創建索引
      await db
        .collection("id_mappings")
        .createIndex({ numericId: 1 }, { unique: true });
      await db
        .collection("id_mappings")
        .createIndex({ objectId: 1 }, { unique: true });

      console.log("ID 映射集合初始化完成");
    }
  } catch (error) {
    console.error("初始化 ID 映射錯誤:", error);
  }
}

// 獲取下一個數字 ID
async function getNextId() {
  const db = await getDB();
  const result = await db
    .collection("counters")
    .findOneAndUpdate(
      { _id: "numericId" },
      { $inc: { seq: 1 } },
      { returnDocument: "after" }
    );
  return result.seq;
}

// 根據數字 ID 獲取 ObjectId
async function getObjectIdFromNumericId(numericId) {
  const db = await getDB();
  const mapping = await db.collection("id_mappings").findOne({
    numericId: parseInt(numericId, 10),
    collection: "todos",
  });

  if (!mapping) {
    return null;
  }

  return mapping.objectId;
}

// 根據 ObjectId 獲取數字 ID
async function getNumericIdFromObjectId(objectId) {
  const db = await getDB();
  const mapping = await db.collection("id_mappings").findOne({
    objectId: objectId,
    collection: "todos",
  });

  if (!mapping) {
    // 如果映射不存在，創建新的映射
    const numericId = await getNextId();
    await db.collection("id_mappings").insertOne({
      objectId: objectId,
      numericId: numericId,
      collection: "todos",
    });
    return numericId;
  }

  return mapping.numericId;
}

// 重置計數器
async function resetCounter() {
  try {
    const db = await getDB();

    // 刪除現有的計數器
    await db.collection("counters").deleteOne({ _id: "numericId" });

    // 創建新的計數器，從 0 開始
    await db.collection("counters").insertOne({ _id: "numericId", seq: 0 });
    console.log("計數器已重置");
    return true;
  } catch (error) {
    console.error("重置計數器錯誤:", error);
    return false;
  }
}

// 重新排序待辦事項 ID
async function resequenceIds() {
  try {
    const db = await getDB();

    // 清空映射集合
    try {
      await db.collection("id_mappings").drop();
      console.log("ID 映射集合已清空");
    } catch (error) {
      // 集合可能不存在，忽略錯誤
      console.log("ID 映射集合不存在或無法刪除");
    }

    // 創建新的映射集合
    await db.createCollection("id_mappings");

    // 獲取所有待辦事項，按創建時間排序
    const todos = await db
      .collection("todos")
      .find({})
      .sort({ createdAt: 1 })
      .toArray();
    console.log(`找到 ${todos.length} 個待辦事項進行重新排序`);

    // 重新映射 ID
    for (const todo of todos) {
      const newId = await getNextId();
      await db.collection("id_mappings").insertOne({
        objectId: todo._id,
        numericId: newId,
        collection: "todos",
      });
      console.log(`已映射: ${todo._id} -> ${newId}`);
    }

    // 創建索引
    await db
      .collection("id_mappings")
      .createIndex({ numericId: 1 }, { unique: true });
    await db
      .collection("id_mappings")
      .createIndex({ objectId: 1 }, { unique: true });

    console.log("ID 重新排序完成");
    return true;
  } catch (error) {
    console.error("ID 重新排序錯誤:", error);
    return false;
  }
}

// 檢查 ID 順序是否需要重排
async function checkAndResequenceIds() {
  try {
    const db = await getDB();

    // 獲取所有映射，按 numericId 排序
    const mappings = await db
      .collection("id_mappings")
      .find({ collection: "todos" })
      .sort({ numericId: 1 })
      .toArray();

    // 檢查是否有間隔
    let needsResequencing = false;
    for (let i = 0; i < mappings.length; i++) {
      // ID 應該從 1 開始連續
      if (mappings[i].numericId !== i + 1) {
        needsResequencing = true;
        break;
      }
    }

    // 如果需要重排
    if (needsResequencing) {
      console.log("檢測到 ID 序列不連續，正在重新排序...");
      await resetCounter();
      await resequenceIds();
      return true;
    }

    return false;
  } catch (error) {
    console.error("檢查 ID 順序錯誤:", error);
    return false;
  }
}

// 1. 獲取待辦事項列表 - GET 方法 (使用 ID 映射)
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

    // 將每個待辦事項的 ObjectId 轉換為數字 ID
    const todosWithNumericIds = await Promise.all(
      todos.map(async (todo) => {
        const numericId = await getNumericIdFromObjectId(todo._id);
        return {
          ...todo,
          _id: numericId,
        };
      })
    );

    // 返回用戶的待辦事項列表
    return res.status(200).json(todosWithNumericIds);
  } catch (error) {
    console.error("獲取待辦事項錯誤:", error);
    return res.status(401).json({ message: "未授權" });
  }
});

// 2. 新增待辦事項 - POST 方法 (使用新的請求格式)
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
    // 從新的請求格式中提取待辦事項數據
    const todoData = req.body.todo;
    console.log("POST: 提取的待辦事項數據:", todoData);

    // 檢查請求體格式，支持單個對象或對象數組
    const isBulkOperation = Array.isArray(todoData);
    const todoItems = isBulkOperation ? todoData : [todoData];

    if (!todoData || todoItems.length === 0) {
      return res.status(400).json({ message: "未提供待辦事項數據" });
    }

    // 創建待辦事項並建立映射
    const createdTodos = [];

    for (const item of todoItems) {
      // 取出標題並驗證
      let title = item.title;
      title = title && title.trim() !== "" ? title.trim() : undefined;

      if (title === undefined) {
        continue; // 跳過無效數據
      }

      // 創建新的待辦事項（使用 MongoDB 的 ObjectId）
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

      // 為新待辦事項創建數字 ID 映射
      const numericId = await getNextId();
      console.log("POST: 獲取的新數字ID:", numericId);

      const mapping = {
        objectId: result.insertedId,
        numericId: numericId,
        collection: "todos",
      };
      console.log("POST: 準備插入的映射:", mapping);

      await db.collection("id_mappings").insertOne(mapping);
      console.log("POST: 映射插入成功");

      // 添加到結果數組
      createdTodos.push({
        ...newTodo,
        _id: numericId,
      });
    }

    if (createdTodos.length === 0) {
      return res.status(400).json({ message: "所有待辦事項標題無效" });
    }

    // 決定返回格式，單個或數組
    const responseData = isBulkOperation ? createdTodos : createdTodos[0];

    // 使用新格式返回創建的待辦事項
    return res.status(201).json({ todo: responseData });
  } catch (error) {
    console.error("新增待辦事項錯誤:", error);
    return res.status(401).json({ message: "未授權" });
  }
});

// 3. 更新待辦事項 - PUT 方法 (使用新的請求格式)
app.put("/todos/:id", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;
    console.log(`用戶ID: ${userId}`);

    // 從路徑參數獲取待辦事項數字ID
    const numericId = parseInt(req.params.id, 10);
    console.log(`待辦事項數字ID: ${numericId}`);

    // 簡單驗證待辦事項ID
    if (isNaN(numericId)) {
      return res.status(401).json({ message: "未授權" });
    }

    // 從新的請求格式中提取待辦事項數據
    console.log("PUT: 原始請求體:", req.body);
    const todoData = req.body.todo || {};
    console.log("更新數據:", todoData);

    // 將數字 ID 轉換為 ObjectId
    const todoObjectId = await getObjectIdFromNumericId(numericId);
    console.log(`對應的 ObjectId: ${todoObjectId}`);

    if (!todoObjectId) {
      console.log("PUT: 找不到ID映射，可能是ID映射集合中沒有此記錄");
      return res.status(404).json({ message: "待辦事項不存在" });
    }

    // 將字符串 ID 轉換為 ObjectId
    const userObjectId = new mongoose.Types.ObjectId(userId);
    console.log("PUT: 用戶ObjectId:", userObjectId);

    // 從請求體獲取更新的欄位
    const { title, completed } = todoData;

    // 準備更新數據
    const updateData = {};

    // 簡化驗證：如果標題有提供且不為空，則加入更新數據
    if (title !== undefined) {
      updateData.title =
        title && title.trim() !== "" ? title.trim() : undefined;
      if (updateData.title === undefined) {
        delete updateData.title;
      }
    }

    // 如果完成狀態有提供，則加入更新數據
    if (completed !== undefined) {
      updateData.completed = !!completed; // 轉換為布林值
    }

    // 添加更新時間，使用 ISO 日期格式
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
      return res.status(401).json({ message: "未授權" });
    }

    // 返回更新後的待辦事項，使用數字 ID
    const updatedTodo = {
      ...result,
      _id: numericId,
    };

    // 使用新格式返回更新後的待辦事項
    return res.status(200).json({ todo: updatedTodo });
  } catch (error) {
    console.error("更新待辦事項錯誤:", error);
    return res.status(401).json({ message: "未授權" });
  }
});

// 4. 刪除待辦事項 - DELETE 方法 (含自動 ID 重排)
app.delete("/todos/:id", verifyToken, async (req, res) => {
  // #swagger.tags = ['Todos']
  try {
    const db = await getDB();

    // 從令牌中獲取用戶ID
    const userId = req.user.id;

    // 從路徑參數獲取待辦事項數字ID
    const numericId = parseInt(req.params.id, 10);

    // 簡單驗證待辦事項ID
    if (isNaN(numericId)) {
      return res.status(401).json({ message: "未授權" });
    }

    // 將數字 ID 轉換為 ObjectId
    const todoObjectId = await getObjectIdFromNumericId(numericId);
    if (!todoObjectId) {
      return res.status(404).json({ message: "待辦事項不存在" });
    }

    // 將字符串 ID 轉換為 ObjectId
    const userObjectId = new mongoose.Types.ObjectId(userId);

    // 確保刪除的是用戶自己的待辦事項
    const result = await db.collection("todos").deleteOne({
      _id: todoObjectId,
      userId: userObjectId,
    });

    // 如果找不到對應的待辦事項或不屬於當前用戶
    if (result.deletedCount === 0) {
      return res.status(401).json({ message: "未授權" });
    }

    // 刪除 ID 映射
    await db.collection("id_mappings").deleteOne({
      objectId: todoObjectId,
      collection: "todos",
    });

    // 檢查並自動重排 ID
    await checkAndResequenceIds();

    // 返回刪除成功的訊息
    return res.status(200).json({ message: "已刪除" });
  } catch (error) {
    console.error("刪除待辦事項錯誤:", error);
    return res.status(401).json({ message: "未授權" });
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

// 在資料庫連接成功後創建 ID 映射和索引
mongoose.connection.once("open", async () => {
  // 初始化 ID 映射
  await initializeIdMapping();

  // 檢查並自動重排 ID
  await checkAndResequenceIds();

  // 創建待辦事項索引
  await createTodoIndexes();

  console.log("應用啟動時 ID 檢查和重排完成");
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
