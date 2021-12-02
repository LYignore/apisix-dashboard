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

package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/shiningrush/droplet"
)

func ParseHStoken(ctx droplet.Context, tokenStr string, loginType string, pubN string, pubE string) (bool, jwt.MapClaims, error) {

	var (
		publicKey *rsa.PublicKey
		_pubN     *big.Int
		_pubE     *big.Int
	)

	if loginType == "WxIAM" {
		_pubN, _ = Parse2bigInt(pubN)
		_pubE, _ = Parse2bigInt(pubE)
	}

	//1.根据 publickey 解析
	publicKey = &rsa.PublicKey{
		N: _pubN,
		E: int(_pubE.Int64()),
	}

	parts := strings.Split(tokenStr, ".")

	if len(parts) < 3 {
		return false, nil, errors.New("parts lens must less than 3")
	}
	err := jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], publicKey)

	if err != nil {
		return false, nil, err
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})

	if err != nil {
		return false, nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, nil, errors.New("failed to cast to jwt.mapclaims")
	}

	if err := token.Claims.Valid(); err != nil {
		return false, nil, err
	}

	return true, claims, nil
}

// parse string to big.Int
func Parse2bigInt(s string) (bi *big.Int, err error) {
	bi = &big.Int{}
	b, err := base64.RawURLEncoding.DecodeString(s) //此处使用的是RawURLEncoding
	if err != nil {
		return
	}
	bi.SetBytes(b)
	return
}
