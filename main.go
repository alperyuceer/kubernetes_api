package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var once sync.Once
var clientset *kubernetes.Clientset
var kubeconfig *string
var kubeconfigErr error
var secretKey = []byte("alper123")

func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")
	r.GET("/login", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "login.html", gin.H{})
	})

	r.GET("/", func(c *gin.Context) {
		namespaces := GetNamespaces()
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Namespaces": namespaces,
		})
	})
	r.GET("/deployment/:namespace/:deploymentName", authenticateMiddleware, func(c *gin.Context) {
		namespace := c.Param("namespace")
		deploymentName := c.Param("deploymentName")

		deployment, err := clientset.AppsV1().Deployments(namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		deploymentDetailsJSON, _ := json.MarshalIndent(deployment, "", "  ")
		c.HTML(http.StatusOK, "deployment_details.html", gin.H{
			"Deployment": string(deploymentDetailsJSON),
			"Namespace":  namespace,
		})
	})

	r.POST("/", func(c *gin.Context) {
		action := c.PostForm("action")
		namespace := c.PostForm("namespace")

		switch action {
		case "pods":
			pods := GetPods(namespace)
			c.HTML(http.StatusOK, "pods.html", gin.H{
				"Pods": pods,
			})
		case "deployments":
			deployments := GetDeployments(namespace)
			c.HTML(http.StatusOK, "deployments.html", gin.H{
				"Deployments": deployments,
				"Namespace":   namespace,
			})
		case "svcs":
			svcs := GetSvc(namespace)
			c.HTML(http.StatusOK, "services.html", gin.H{
				"Svcs": svcs,
			})
		}
	})

	r.POST("/login", loginHandler)
	r.POST("/register", registerHandler)

	r.Run(":8081")
}

func loadClientset() {
	once.Do(func() {
		config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			kubeconfigErr = err
			return
		}
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			kubeconfigErr = err
			return
		}
	})
}

func init() {
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "")
	}
	flag.Parse()

	loadClientset()
}

func GetDeployments(namespace string) []map[string]string {
	if kubeconfigErr != nil {
		panic(kubeconfigErr.Error())
	}
	loadClientset()

	deployments, err := clientset.AppsV1().Deployments(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	var deploymentList []map[string]string
	for _, deployment := range deployments.Items {
		deploymentMap := make(map[string]string)
		deploymentMap["name"] = deployment.Name
		deploymentMap["namespace"] = namespace
		deploymentList = append(deploymentList, deploymentMap)
	}
	return deploymentList
}

func GetNamespaces() []string {
	if kubeconfigErr != nil {
		panic(kubeconfigErr.Error())
	}
	loadClientset()

	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	var namespaceNames []string
	for _, namespace := range namespaces.Items {
		namespaceNames = append(namespaceNames, namespace.Name)
	}
	return namespaceNames
}

func GetPods(namespace string) []string {
	if kubeconfigErr != nil {
		panic(kubeconfigErr.Error())

	}
	loadClientset()
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	var podsList []string
	for _, pods := range pods.Items {
		podsList = append(podsList, pods.Name)
	}
	return podsList

}

func GetSvc(namespace string) []string {
	if kubeconfigErr != nil {
		panic(kubeconfigErr.Error())

	}
	loadClientset()
	svcs, err := clientset.CoreV1().Services(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	var svcList []string
	for _, svcs := range svcs.Items {
		svcList = append(svcList, svcs.Name)
	}
	return svcList

}

func loginHandler(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	if !authenticateUser(email, password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email veya şifre hatalı"})
		return
	}

	tokenString, err := createToken(email)
	if err != nil {
		c.String(http.StatusInternalServerError, "Token oluşturulurken sorun oluştur")
		return
	}

	fmt.Printf("Token created: %s\n", tokenString)
	c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  time.Now().Add(10 * time.Minute), // geçerlilik süresi
		HttpOnly: true,
		Secure:   true,
	})
	c.Redirect(http.StatusFound, "/")

	fmt.Println("GİRİŞ YAPILDI")
}

func authenticateUser(email, password string) bool {
	db, err := sql.Open("postgres", "user=postgres password=x35R7iWmuF host=localhost port=5432 dbname=kullanicilar sslmode=disable")
	if err != nil {
		fmt.Println("database'e bağlanmadı:", err)
		return false
	}
	defer db.Close()

	var hashedPassword string
	err = db.QueryRow("SELECT parola FROM kullanicilar WHERE email = $1", email).Scan(&hashedPassword)
	if err != nil {
		fmt.Println("dbden veri çekilemedi:", err)
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Println("parola eşleşmedi:", err)
		return false
	}

	return true
}
func createToken(email string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": email,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	fmt.Printf("Token bilgileri eklendi: %+v\n", claims)
	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func authenticateMiddleware(c *gin.Context) {
	// çerezden tokeni çek
	cookie, err := c.Request.Cookie("token")

	if err != nil {
		// token bulunamadı
		//c.Redirect(http.StatusSeeOther, "/login")
		fmt.Printf("çerezden token bulunamadı     ")
		tokenString := c.GetHeader("Authorization")
		token, err := verifyToken(tokenString)
		if err != nil {
			fmt.Printf("Token verification failed: %v\\n", err)
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		fmt.Printf("Token başarıyla doğrulandı. Claims: %+v\\n", token.Claims)

		return
	}

	tokenString := cookie.Value

	if err != nil {
		fmt.Println("Token missing in cookie")
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// token doğrula
	token, err := verifyToken(tokenString)
	if err != nil {
		fmt.Printf("Token verification failed: %v\\n", err)
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	// token bilgileri
	fmt.Printf("Token başarıyla doğrulandı. Claims: %+v\\n", token.Claims)

	c.Next()
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("hatalı token")
	}

	return token, nil
}
func registerHandler(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	if email == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email ve parola boş olamaz"})
		return
	}

	if kullaniciVarmi(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bu email ile zaten kayıtlı bir kullanıcı var"})
		return
	}

	if err := kullaniciEkle(email, password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı eklenirken bir hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Kayıt başarıyla tamamlandı"})
}

func kullaniciVarmi(email string) bool {
	db, err := sql.Open("postgres", "user=postgres password=x35R7iWmuF host=localhost port=5432 dbname=kullanicilar sslmode=disable")
	if err != nil {
		fmt.Println("Hata", err)

	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM kullanicilar WHERE email = $1", email).Scan(&count)
	if err != nil {
		fmt.Println("Hata", err)

	}

	return count > 0
}

func kullaniciEkle(email, password string) error {
	db, err := sql.Open("postgres", "user=postgres password=x35R7iWmuF host=localhost port=5432 dbname=kullanicilar sslmode=disable")
	if err != nil {
		fmt.Println("Hata", err)
	}
	defer db.Close()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Hata", err)
		return err
	}

	_, err = db.Exec("INSERT INTO kullanicilar (email, parola) VALUES ($1, $2)", email, string(hashedPassword))
	if err != nil {
		fmt.Println("Hata", err)
	}

	return nil
}
