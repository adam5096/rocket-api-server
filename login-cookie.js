// 匯入 http 框架 express
const express = require('express')
const cookieParser = require("cookie-parser");

// 建立 express 物件
const app = express()
// 建立 server 服務所在 port
const port = 3000

app.use(cookieParser());

// ====== 建立路由規則 ======
// 設置 cookie
app.get('/set-cookie', (req, res) => {
    // name: cookie 名稱
    // adam: cookie 值
    // cookie 特性:
    // 1. 會在瀏覽器關閉時銷毀
    res.cookie('name', 'adam', {maxAge: 180 * 1000})
    res.cookie('theme', 'blue')
    res.send("Hello World!");
})

// 刪除 cookie
app.get('/remove-cookie', (req, res) => {
    // 使用場景: user logout
    res.clearCookie('name')
    res.send('刪除成功~~')
})

// 取出 cookie
app.get('/get-cookie', (req, res) => {
    console.log(req.cookies);
    // res.send('取出 cookie')
    res.send(`歡迎 ${req.cookies.name}`);

})




// ====== 建立路由規則 END ======

// server 服務啟用訊息
app.listen(port, () => console.log(`Example app listening on port ${port}!`))