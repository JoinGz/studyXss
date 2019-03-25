let express = require('express')
let app = express()
let path = require('path')
let csrf = require('csurf')
let csurfAuth = csrf()
let bodyParser = require('body-parser')
let xss = require('xss')
let xssOptions = {
  whiteList: {
    a: ["href", "title", "target"],
    p: ['class', 'id']
  },
  escape: function escapeHtml(html) {
    return html.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
}
let myxss = new xss.FilterXSS(xssOptions);

// let cookieParser = require('cookie-parser')
// express-session 用于处理用户 session
let session = require('express-session')
var static = path.resolve(__dirname)
app.use(express.static(static))
app.set('views', path.join(__dirname))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded())
// app.use(cookieParser())
// 使服务器支持session
app.use(
  session({
    //我们使用一串随机字符串来对客户端的 session 进行编码。这样就能在一定程度上增加 cookies 的安全性。
    //而将 resave 设置为 true 则保证了即使 session 没有被修改也依然会被刷新。
    secret: 'TKRv0IJs=HYqrvagQ#&!F!%V]Ww/4KiVs$s,<<MX',
    resave: true,
    saveUninitialized: true,
    rolling: true, // 使cookie和session保存时间顺延
    // 毫秒(一周)
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
)
// 使用方法
app.use(csurfAuth)
app.get('/', (req, res) => {
  res.render('index', {
    auth: req.csrfToken()
  })
})
// 中间件方法。错误处理在其中
// app.post('*',csurfAuth,(err,req,res,next)=>{
//   if (err.code === 'EBADCSRFTOKEN') {
//     console.log('翻车')
//     res.status(403)
//     res.send('form tampered with')
//     return 
//   }else {
//     next()
//   }
// })
app.post('/test', (request, response, next) => {
  response.render('form', {
    auth: request.csrfToken()
  })
})
app.get('/json', (req, res) => {
  let json = require('./package.json')
  console.log(json);
  res.end(JSON.stringify(json))
})
app.post('/xss', (req, res) => {
  req.body.text = myxss.process(req.body.text);
  console.log(req.body.text);
  
  req.body.text = req.body.text.replace(/amp;/g, '');
  res.render('xss', {
    text: req.body.text
  })
})
// 使用方法的错误处理
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // CSRF验证失败
  res.status(403)
  res.send('验证数百')
})

app.listen(8080, () => {
  console.log('8080 is opening')
})