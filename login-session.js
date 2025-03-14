const express = require("express");
// 一支專門處理 session 的 express middleware
const session = require("express-session");
const MongoStore = require("connect-mongo");
const app = express();
const port = 3000;

// 設置 session 中間件
app.use(
  session({
    name: "sid", // 設置 cookie 的 name。預設是 connect.sid
    secret: "atauigu", // 簽名: 參與加密的字串
    saveUninitialized: false, // 是否為每次請求都設置一個 cookie 來保存 session id
    reave: true, // 是否在每次請求時都重新保存 session
    store: MongoStore.create({
      mongoUrl: "mongodb://127.0.0.1:27017/project", // 資料庫連結設置
    }),
    cookie: {
      // path: ,cookie 存放在 client 端位置
      httpOnly: true, // 開啟後，前端無法通過 JS 操作，是否由後端修改 cookie
      // secure: ,是否使用 https
      maxAge: 1000 * 60 * 5, // session id 過期時間
    },
  })
);

app.get("/", (req, res) => res.send("Hello World!"));

// 登入 與 檢查 帳號密碼
app.get("/login", (req, res) => {
  // username-admin, password-admin
  // 檢查通過條件後，才會設置 session
  if (req.query.username === "admin" && req.query.password === "admin") {
    // 設置 session
    req.session.username = "admin";
    req.session.uid = "uwei651";
    //操作成功回應
    res.send("登入成功");
  } else {
    res.send("登入失敗");
  }
});

// 查看購物車頁:需登入
app.get("/cart", (req, res) => {
  // 檢查 session 當前 user 操作是否都處在帳號已登入狀態
  // 檢查 user 數據
  if (req.session.username) {
    res.send(`購物車頁面，歡迎您! ${req.session.username} `);
  } else {
    res.send("你還未登入");
  }
});

// 使用者登出
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
      res.send('登出成功~~ !')
  })
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
