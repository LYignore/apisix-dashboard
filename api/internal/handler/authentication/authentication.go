/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package authentication

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/shiningrush/droplet"
	"github.com/shiningrush/droplet/wrapper"
	wgin "github.com/shiningrush/droplet/wrapper/gin"

	"github.com/apisix/manager-api/internal/conf"
	"github.com/apisix/manager-api/internal/handler"
	"github.com/apisix/manager-api/internal/log"
	"github.com/apisix/manager-api/internal/utils"
	"github.com/apisix/manager-api/internal/utils/consts"
)

type Handler struct {
}

func NewHandler() (handler.RouteRegister, error) {
	return &Handler{}, nil
}

func (h *Handler) ApplyRoute(r *gin.Engine) {
	r.POST("/apisix/admin/user/login", wgin.Wraps(h.userLogin,
		wrapper.InputType(reflect.TypeOf(LoginInput{}))))
	r.GET("/apisix/admin/user/logout", wgin.Wraps(h.userLogout,
		wrapper.InputType(reflect.TypeOf(UserLogoutInput{}))))
	r.POST("/apisix/admin/user/wxiamauth", wgin.Wraps(h.userWxIAMAuth,
		wrapper.InputType(reflect.TypeOf(AuthorizedLoginInput{}))))
	r.POST("/apisix/admin/user/wxiamlogin", wgin.Wraps(h.userWxIAMLogin,
		wrapper.InputType(reflect.TypeOf(IamLoginInput{}))))
}

type UserSession struct {
	LoginType   string `json:"login_type"`
	AccessToken string `json:"access_token"`
	Token       string `json:"id_token"`
	Exp         string `json:"exp"`
	Iat         string `json:"iat"`
	Sub         string `json:"sub"`
}

// swagger:model LoginInput
type LoginInput struct {
	// user name
	Username string `json:"username" validate:"required"`
	// password
	Password string `json:"password" validate:"required"`
}

type IdpLoginInput struct {
	IdToken string `json:"id_token" validate:"required"`
}

type IamLoginInput struct {
	// user name
	Username string `json:"username" validate:"required"`
	// password
	Password string `json:"password" validate:"required"`
}

type AuthorizedLoginInput struct {
	IdToken string `json:"id_token" validate:"required"`
}

type WxIAMLogin struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type UserLogoutInput struct {
	IdToken   string `auto_read:"Authorization,header" json:"Authorization" validate:"required"`
	LoginType string `auto_read:"loginType,header" json:"loginType" validate:"required"`
}

// swagger:operation POST /apisix/admin/user/login userLogin
//
// user login.
//
// ---
// produces:
// - application/json
// parameters:
// - name: username
//   in: body
//   description: user name
//   required: true
//   type: string
// - name: password
//   in: body
//   description: password
//   required: true
//   type: string
// responses:
//   '0':
//     description: login success
//     schema:
//       "$ref": "#/definitions/ApiError"
//   default:
//     description: unexpected error
//     schema:
//       "$ref": "#/definitions/ApiError"
func (h *Handler) userLogin(c droplet.Context) (interface{}, error) {
	input := c.Input().(*LoginInput)
	username := input.Username
	password := input.Password

	user := conf.UserList[username]
	if username != user.Username || password != user.Password {
		return nil, consts.ErrUsernamePassword
	}

	// create JWT for session
	claims := jwt.StandardClaims{
		Subject:   username,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Second * time.Duration(conf.AuthConf.ExpireTime)).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(conf.AuthConf.Secret))

	// output token
	return &UserSession{
		Token: signedToken,
		Sub:       username,
		LoginType: "Basic",
	}, nil
}

func (h *Handler) userWxIAMAuth(c droplet.Context) (interface{}, error) {
	loginType := "WxIAM"
	input := c.Input().(*AuthorizedLoginInput)
	id_token := input.IdToken
	sub, idToken, _err := authorizedLogin(c, loginType, id_token)
	return &UserSession{
		Token:     idToken,
		Sub:       sub,
		LoginType: loginType,
	}, _err
}

func (h *Handler) userWxIAMLogin(c droplet.Context) (interface{}, error) {
	var rep map[string]interface{}
	var accessToken string
	var idToken string

	input := c.Input().(*IamLoginInput)
	username := input.Username
	password := input.Password

	if username == "" {
		log.Errorf("%s", consts.ErrLoginNeedUserName)
		return nil, consts.ErrLoginNeedUserName
	}
	if password == "" {
		log.Errorf("%s", consts.ErrLoginNeedUserName)
		return nil, consts.ErrLoginNeedPassWord
	}

	//生成要访问的url
	postURL := conf.IamConf.WxIAMLoginURL
	loginParam := WxIAMLogin{ClientId: conf.IamConf.WxIAMClientID, ClientSecret: conf.IamConf.WxIAMClientSecret, Username: username, Password: password}
	loginParamJSON, _ := json.Marshal(loginParam)
	//提交请求
	response, err := http.Post(postURL, "application/json", strings.NewReader(string(loginParamJSON)))

	if err != nil {
		log.Errorf("%s: %s", consts.ErrWxIAMLogin, err)
		return nil, consts.ErrWxIAMLogin
	}

	defer response.Body.Close()

	//处理返回结果
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("%s: %s", consts.ErrWxIAMResponse, err)
		return nil, consts.ErrWxIAMResponse
	}

	if err := json.Unmarshal([]byte(string(responseBody)), &rep); err == nil {
		if _, ok := rep["accessToken"]; ok {
			// accessToken存在
			accessToken = rep["accessToken"].(string)
		}
		if _, ok := rep["id_token"]; ok {
			// id_token存在
			idToken = rep["id_token"].(string)
		}
	} else {
		log.Errorf("%s: %s", consts.ErrWxIAMResponse, err)
		return nil, consts.ErrWxIAMResponse
	}

	pubN := conf.IamConf.WxIAMN
	pubE := conf.IamConf.WxIAME
	sub, err := utils.GetSub(c, "WxIAM", idToken, pubN, pubE)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == 200 && sub != "" {
		errorNumber := rep["errorNumber"]
		//isError := false
		if value, ok := errorNumber.(float64); ok {
			fmt.Println("errorNumber===>", value)

			// output token
			return &UserSession{
				LoginType:   "WxIAM",
				AccessToken: accessToken,
				Token:       idToken,
				Sub:         sub,
			}, nil
		} else {
			log.Errorf("%s: %s", consts.ErrWxIAMServer, err)
			return nil, consts.ErrWxIAMServer
		}
	} else {
		log.Errorf("%s: %s", consts.ErrWxIAMServer, err)
		return nil, consts.ErrWxIAMServer
	}
}

func authorizedLogin(c droplet.Context, loginType string, idToken string) (string, string, error) {
	var pubN string
	var pubE string
	if idToken != "" {
		if loginType == "WxIAM" {
			pubN = conf.IamConf.WxIAMN
			pubE = conf.IamConf.WxIAME
		}
		sub, err := utils.GetSub(c, loginType, idToken, pubN, pubE)

		if sub == "" {
			return sub, idToken, fmt.Errorf("sub connot nil")
		} else {
			return sub, idToken, err
		}
	} else {
		return "", idToken, fmt.Errorf("idToken is nil")
	}
}

func (h *Handler) userLogout(c droplet.Context) (interface{}, error) {
	loginType := "basic"
	input := c.Input().(*UserLogoutInput)
	idToken := input.IdToken
	loginType = input.LoginType

	if loginType != "basic" {
		if loginType == "WxIAM" {
			logoutURL := conf.IamConf.WxIAMLogoutURL + "?access_token=" + idToken
			response, _ := http.Get(logoutURL)
			fmt.Println("response====>", response)
		}
	}
	return &UserSession{
		Token:     idToken,
		LoginType: loginType,
	}, nil
}
