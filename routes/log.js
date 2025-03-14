// ====== middleware 務必寫在 使用路由 區塊之前 ======
// middleware 專注處理所有在 request 與 response 兩者之間共同會發生的事情: 例如日誌、登入驗證
const serverLogMiddleWare = (req, res, next) => {
  // 日誌集中在中間件統一管理
  console.log(`log:[${req.method}]:${req.url} --- ${new Date().toISOString()}`);
  // next() 重點: middleware 執行完後，express 會繼續為你的 request 尋路
  next();
};

app.use(serverLogMiddleWare);