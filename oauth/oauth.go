package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/sharkx018/bookstore_utils-go/rest_errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	userRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 100 * time.Millisecond,
	}
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "x-Caller-Id"

	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func AuthenticationRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	//http://localhost:8080/api/users?access_token=123abc
	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		//if err.Status == http.StatusNotFound {
		//	return nil
		//}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil

}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenID string) (*accessToken, rest_errors.RestErr) {
	response := userRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))

	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to to get access token", errors.New("restclient error"))
	}

	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("invalid err interface when trying to get access token", errors.New("restclient error"))
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("restclient error"))
	}
	return &at, nil
}
