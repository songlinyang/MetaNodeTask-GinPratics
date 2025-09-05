package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// JWT默认密钥
var jwtSerect = []byte("123456")

// user用户对象参数值
type UserRegister struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,passwordReg"`
}

type UserLogin struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// 获取从数据库获取数据
type UserTableScan struct {
	Username string `db:"username" json:"username,omitempty"`
	Password string `db:"password" json:"password,omitempty"`
	Token    string `db:"token" json:"toekn,omitempty"`
}
type User struct {
	ID        int64     `db:"id" json:"id"`
	Username  string    `db:"username" json:"username" binding:"required"`
	Password  string    `db:"password" json:"password" binding:"required"`
	Token     string    `db:"token" json:"token,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// 生成JWT令牌
type MyClaims struct {
	Username      string   `json:"username"`
	Roles         []string `json:"roles"`
	Exp           int64    `json:"exp"`
	jwt.MapClaims          //这个是用来继承MapClaims的实现
}

// @title Gin Web API
// @version 1.0
// @description RESTful API 文档示例
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /

// @securityDefinitions.basic BasicAuth
func initDB() (*sqlx.DB, error) {
	var (
		dsn = "identifier.sqlite"
	)
	db, err := sqlx.Connect("sqlite3", dsn)
	if err != nil {
		panic(err)
	}
	//创建表
	schema := `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
	token TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`
	_, err1 := db.Exec(schema)
	if err1 != nil {
		panic(err1)
	}

	return db, nil
}
func main() {
	//初始化数据库
	db, err := initDB()
	if err != nil {
		log.Fatal("数据库初始化失败:", err)
	}
	defer db.Close()   //每次数据库退出操作时，都能进行close关闭
	r := gin.Default() //定义路由

	// 注册自定义验证器
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("passwordReg", passwordValidatorCustom)
	}

	// 添加docs路由（main函数内）
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 配置swagger.json路径（初始化路由前添加）
	r.StaticFile("/swagger.json", "./docs/swagger.json")

	// 添加文档访问中间件
	authMiddleware := gin.BasicAuth(gin.Accounts{
		"admin": "admin123",
	})
	r.GET("/docs", authMiddleware, ginSwagger.WrapHandler(swaggerFiles.Handler))
	// open and connect at the same time:
	//r.Use(JwtMidderWare(db))
	//注册用户，并返回jwt
	r.POST("/register", registerUser(db))
	//r.Use(JWTAuth())
	r.POST("/login", userLogin(db))
	/**

	 */
	// 全局中间件执行顺序验证 （除了注册登录结构）
	r.Use(
		LatencyLogger(),  //日志中间件
		CORSMiddleware(), //CORS跨域中间件
	)
	v1 := r.Group("/api/v1")
	{
		authApi := v1.Group("auth")
		authApi.Use(JWTAuth()) //添加jwt鉴权中间件
		//获取用户信息
		// 获取用户信息接口
		// @Summary 获取用户信息
		// @Tags auth
		// @Produce json
		// @Security ApiKeyAuth
		// @Success 200 {object} gin.H "用户信息"
		// @Failure 403 {object} gin.H "权限不足"
		// @Router /api/v1/auth/userInfo [get]
		// authApi.GET("/userInfo", func(c *gin.Context) { ... })

		authApi.GET("/userInfo", func(c *gin.Context) {
			requestID := c.MustGet("requestID").(string)
			username := c.MustGet("username")
			roles := c.MustGet("roles")
			exp := c.MustGet("exp")
			c.JSON(http.StatusOK, gin.H{
				"requestID": requestID,
				"username":  username,
				"roles":     roles,
				"exp":       exp,
				"msg":       "用户信息获取成功!",
			})
		})
		//更新用户信息
		//authApi.POST('/userInfo')
		//删除用户信息
		//authApi.DELETE('/userInfo')

		//角色权限管理
		adminApi := v1.Group("admin")
		adminApi.Use(
			JWTAuth(), //添加jwt鉴权中间件
			RequireRole("admin"),
		)
		//获取vip用户信息
		// 获取VIP用户信息接口
		// @Summary 获取VIP用户信息
		// @Tags admin
		// @Produce json
		// @Security ApiKeyAuth
		// @Success 200 {object} gin.H "VIP用户信息"
		// @Failure 403 {object} gin.H "权限不足"
		// @Router /api/v1/admin/userInfo [get]
		// adminApi.GET("/userInfo", func(c *gin.Context) { ... })
		adminApi.GET("/userInfo", func(c *gin.Context) {
			requestID := c.MustGet("requestID").(string)
			username := c.MustGet("username")
			roles := c.MustGet("roles")
			exp := c.MustGet("exp")
			c.JSON(http.StatusOK, gin.H{
				"requestID": requestID,
				"username":  username,
				"roles":     roles,
				"exp":       exp,
				"msg":       "获取vip用户信息成功",
			})
		})
	}

	r.Run(":8080")

}

// 用户登录校验
// 用户登录接口
// @Summary 用户登录
// @Tags auth
// @Accept  json
// @Produce json
// @Param   login body UserLogin true "用户登录信息"
// @Success 200 {object} map[string]interface{} "登录成功"
// @Failure 400 {object} map[string]interface{} "参数校验失败或用户名密码错误"
// @Router /login [post]
func userLogin(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginUser UserLogin
		if err := c.ShouldBindJSON(&loginUser); err != nil {
			errors := err.(validator.ValidationErrors)
			errorMessages := make([]string, len(errors))
			for i, e := range errors {
				errorMessages[i] = fmt.Sprintf("参数 %s 校验失败：%s", e.Field(), e.Tag())
			}
			//			| 错误码 | 说明         |
			//			|--------|--------------|
			//			| 1001   | 参数校验失败 |
			//			| 1002   | 认证失败     |
			//			| 2001   | 数据库错误   |
			//			- 标准化响应格式
			//			- 版本控制方案
			//			- 接口文档生成
			c.JSON(http.StatusBadRequest, gin.H{
				"code":   1001,
				"msg":    "参数校验失败",
				"errors": errorMessages,
			})
			return
		}
		fmt.Println(loginUser)
		//检查用户登录的用户名和密码是否存在数据库中
		var userTableScan UserTableScan
		err := db.Get(&userTableScan, "select username,password,token from users where username=?", loginUser.Username)
		if userTableScan.Username == "" {
			c.JSON(400, gin.H{
				"code":   "400",
				"msg":    "用户未注册",
				"errors": err,
			})
			return
		}
		//如果存在则取出,比对密码hash值，如果相等则表示用户名密码一致
		if userTableScan.Password != hashPassword(loginUser.Password) {
			c.JSON(400, gin.H{
				"code": "400",
				"msg":  "用户名或密码不一致",
			})
			return
		}
		//判断token是否失效
		c.JSON(http.StatusOK, gin.H{
			"code":  200,
			"msg":   "用户登录成功",
			"token": userTableScan.Token,
		})
	}
}

// 注册用户名，注册成功进行入库保存，并且把jwt token一起保存入库
// Swagger注释模板示例

// 用户注册接口
// @Summary 用户注册
// @Tags auth
// @Accept  json
// @Produce json
// @Param   register body UserRegister true "用户注册信息"
// @Success 200 {object} map[string]interface{} "注册成功"
// @Failure 400 {object} map[string]interface{} "参数校验失败或用户名已存在"
// @Failure 500 {object} map[string]interface{} "服务器内部错误"
// @Router /register [post]
func registerUser(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var userRegister UserRegister
		if err := c.ShouldBindJSON(&userRegister); err != nil {
			errors := err.(validator.ValidationErrors)
			errorMessages := make([]string, len(errors))
			for i, e := range errors {
				errorMessages[i] = fmt.Sprintf("参数 %s 校验失败：%s", e.Field(), e.Tag())
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"code":   1001,
				"msg":    "参数校验失败",
				"errors": errorMessages,
			})
			return
		}
		//检查用户是否存在
		var user User
		err := db.Get(&user, "select id from users where username=?", userRegister.Username)
		if err == nil {
			c.JSON(400, gin.H{
				"code": "400",
				"mgs":  "用户名已存在",
			})
			return
		}
		// 检查用户是否已存在
		//生成token
		roles := []string{"admin"} // 这里使用中间件进行设置，待优化
		//游客权限
		//roles := []string{"guest"} // 这里使用中间件进行设置，待优化

		token, err := GenerateToken(userRegister.Username, roles)
		if err != nil {
			c.JSON(500, gin.H{
				"code":   "500",
				"msg":    "生成token失败",
				"errors": err,
			})
			return
		}
		//加密密码
		hashedPassword := hashPassword(userRegister.Password)
		//插入数据
		sql := "INSERT INTO users (username, password, token) VALUES (?, ?, ?)"
		tx, err := db.Begin() //增加插入事务，如果插入失败则回滚，并报错
		result, err := tx.Exec(sql, userRegister.Username, hashedPassword, token)
		err = tx.Commit()
		if err != nil {
			c.JSON(500, gin.H{
				"code":   "500",
				"msg":    "注册失败",
				"errors": err,
			})
			return
		}
		userID, _ := result.LastInsertId()
		//插入成功，直接返回用户信息
		var msgValue = map[string]interface{}{
			"user_id":  userID,
			"username": userRegister.Username,
		}

		c.JSON(200, gin.H{
			"code": 200,
			"msg":  "注册成功",
			"data": msgValue,
		})
	}
}

/**中间件执行流程
[客户端请求]
    ↓
[Logger中间件] → 记录请求开始时间
    ↓
[CORS中间件] → 处理跨域请求
    ↓
[JWT鉴权] → 验证访问令牌
    ↓
[RBAC鉴权] → 校验用户权限
    ↓
[业务处理] → 核心业务逻辑
    ↓
[Logger中间件] ← 记录响应耗时
**/

// 1.Logger中间件配置
// LatencyLogger 创建一个记录请求耗时的中间件
func LatencyLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 记录请求开始时间
		start := time.Now()

		// 在处理请求之前可以记录一些信息
		fmt.Printf("[%s] %s %s - Request started\n",
			start.Format("2006-01-02 15:04:05"),
			c.Request.Method,
			c.Request.URL.Path)
		// 在中间件中添加调试信息
		c.Set("requestID", uuid.NewString())
		log.Printf("[%s] %s %s", c.GetString("requestID"), c.Request.Method, c.Request.URL)
		// 处理请求
		c.Next()

		// 计算耗时
		latency := time.Since(start)

		// 获取响应状态码
		status := c.Writer.Status()

		// 记录请求完成信息，包括耗时
		fmt.Printf("[%s] %s %s - Completed in %v with status %d\n",
			time.Now().Format("2006-01-02 15:04:05"),
			c.Request.Method,
			c.Request.URL.Path,
			latency,
			status)
	}
}

// 3. RBAC权限中间件配置
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}
		for _, r := range roles.([]string) {
			if r == role {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}

func GenerateToken(username string, roles []string) (string, error) {
	//log.Println("GenerateToken->username", username)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, MyClaims{ //这里改成了自定义的Claims结构体，若使用jwt自带jwt.MapClaims,则无法拿到username。需要理解
		Username: username,
		Roles:    roles,
		Exp:      time.Now().Add(8 * time.Hour).Unix(), //失效时间，8小时失效，观察效果
	})
	return token.SignedString(jwtSerect)
}

// JWTAuth中间件配置
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		//strings.TrimPrefix 移除字符串前缀
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
			return
		}
		//log.Println(tokenString)
		token, err := jwt.ParseWithClaims(tokenString, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
			log.Println(token)
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { //作用是为了验证是基于HMAC（基于哈希的消息认证码）算法系列，而不是RSA或者AES加密。另外不用验证也可以，也不会报错。最好需要进行验证操作
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSerect, nil
		})
		//log.Println(token.Claims.(*MyClaims), err) //
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
			return
		}
		//拿到jwt里面解析后的内容 ，使用*MyClaims对token.Claims进行断言
		if claims, ok := token.Claims.(*MyClaims); ok && token.Valid {
			log.Println("打印获取的用户信息：", claims.Username, claims.Roles, claims.Exp)
			c.Set("username", claims.Username)
			c.Set("roles", claims.Roles)
			c.Set("exp", claims.Exp)
			c.Next()
		}
	}
}

// 2。跨域中间件配置
func CORSMiddleware() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"https://prod.com", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

// 密码加密方法
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// 自定义验证规则
// 自定义绑定密码验证规则，使用正则表达

var passwordValidatorCustom validator.Func = func(fl validator.FieldLevel) bool {
	data, ok := fl.Field().Interface().(string)
	if ok {
		return regexp.MustCompile(`^([0-9].*[a-zA-Z]|[a-zA-Z].*[0-9]).*$`).MatchString(data)
	}
	return ok
}
