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
package upstream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/shiningrush/droplet"
	"github.com/shiningrush/droplet/data"
	"github.com/shiningrush/droplet/wrapper"
	wgin "github.com/shiningrush/droplet/wrapper/gin"

	"github.com/apisix/manager-api/internal/core/entity"
	"github.com/apisix/manager-api/internal/core/store"
	"github.com/apisix/manager-api/internal/handler"
	"github.com/apisix/manager-api/internal/utils"
	"github.com/apisix/manager-api/internal/utils/consts"
)

type Handler struct {
	upstreamStore store.Interface
	routeStore    store.Interface
	serviceStore  store.Interface
}

func NewHandler() (handler.RouteRegister, error) {
	return &Handler{
		upstreamStore: store.GetStore(store.HubKeyUpstream),
		routeStore:    store.GetStore(store.HubKeyRoute),
		serviceStore:  store.GetStore(store.HubKeyService),
	}, nil
}

func (h *Handler) ApplyRoute(r *gin.Engine) {
	r.GET("/apisix/admin/upstreams/:id", wgin.Wraps(h.Get,
		wrapper.InputType(reflect.TypeOf(GetInput{}))))
	r.GET("/apisix/admin/upstreams", wgin.Wraps(h.List,
		wrapper.InputType(reflect.TypeOf(ListInput{}))))
	r.POST("/apisix/admin/upstreams", wgin.Wraps(h.Create,
		wrapper.InputType(reflect.TypeOf(entity.Upstream{}))))
	r.PUT("/apisix/admin/upstreams", wgin.Wraps(h.Update,
		wrapper.InputType(reflect.TypeOf(UpdateInput{}))))
	r.PUT("/apisix/admin/upstreams/:id", wgin.Wraps(h.Update,
		wrapper.InputType(reflect.TypeOf(UpdateInput{}))))
	r.PATCH("/apisix/admin/upstreams/:id", wgin.Wraps(h.Patch,
		wrapper.InputType(reflect.TypeOf(PatchInput{}))))
	r.PATCH("/apisix/admin/upstreams/:id/*path", wgin.Wraps(h.Patch,
		wrapper.InputType(reflect.TypeOf(PatchInput{}))))
	r.DELETE("/apisix/admin/upstreams/:ids", wgin.Wraps(h.BatchDelete,
		wrapper.InputType(reflect.TypeOf(BatchDelete{}))))

	r.GET("/apisix/admin/notexist/upstreams", wgin.Wraps(h.Exist,
		wrapper.InputType(reflect.TypeOf(ExistCheckInput{}))))

	r.GET("/apisix/admin/names/upstreams", wgin.Wraps(h.listUpstreamNames))
}

type GetInput struct {
	ID string `auto_read:"id,path" validate:"required"`
}

func (h *Handler) Get(c droplet.Context) (interface{}, error) {
	input := c.Input().(*GetInput)

	r, err := h.upstreamStore.Get(c.Context(), input.ID)
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	upstream := r.(*entity.Upstream)
	upstream.Nodes = entity.NodesFormat(upstream.Nodes)
	//check creator
	loginUser := c.Get("LoginUser")
	if err := ValidateCreator(loginUser.(string), upstream); err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusForbidden}, err
	}

	return r, nil
}

type ListInput struct {
	Name string `auto_read:"name,query"`
	store.Pagination
}

// swagger:operation GET /apisix/admin/upstreams getUpstreamList
//
// Return the upstream list according to the specified page number and page size, and can search upstreams by name.
//
// ---
// produces:
// - application/json
// parameters:
// - name: page
//   in: query
//   description: page number
//   required: false
//   type: integer
// - name: page_size
//   in: query
//   description: page size
//   required: false
//   type: integer
// - name: name
//   in: query
//   description: name of upstream
//   required: false
//   type: string
// responses:
//   '0':
//     description: list response
//     schema:
//       type: array
//       items:
//         "$ref": "#/definitions/upstream"
//   default:
//     description: unexpected error
//     schema:
//       "$ref": "#/definitions/ApiError"
func (h *Handler) List(c droplet.Context) (interface{}, error) {
	input := c.Input().(*ListInput)

	//validate Creator
	loginUser := c.Get("LoginUser")
	creatorLabel := "API_CREATOR:" + loginUser.(string)
	creatorLabelMap, err := utils.GenLabelMap(creatorLabel)
	if err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
			fmt.Errorf("%s: \"%s\"", err.Error(), creatorLabel)
	}

	ret, err := h.upstreamStore.List(c.Context(), store.ListInput{
		Predicate: func(obj interface{}) bool {
			if loginUser.(string) != "admin" && !utils.LabelContains(obj.(*entity.Upstream).Labels, creatorLabelMap) {
				return false
			}
			if input.Name != "" {
				return strings.Contains(obj.(*entity.Upstream).Name, input.Name)
			}
			return true
		},
		Format: func(obj interface{}) interface{} {
			upstream := obj.(*entity.Upstream)
			upstream.Nodes = entity.NodesFormat(upstream.Nodes)
			return upstream
		},
		PageSize:   input.PageSize,
		PageNumber: input.PageNumber,
	})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (h *Handler) Create(c droplet.Context) (interface{}, error) {
	input := c.Input().(*entity.Upstream)

	// check name existed
	ret, err := handler.NameExistCheck(c.Context(), h.upstreamStore, "upstream", input.Name, nil)
	if err != nil {
		return ret, err
	}

	// check creator in Labels: API_CREATOR is default label, and it is current user
	if input.Labels != nil {
		labelMap, err := utils.GenLabelMap("API_CREATOR")
		if err != nil {
			return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
				fmt.Errorf("%s: \"%s\"", err.Error(), "API_CREATOR")
		}

		if utils.LabelContains(input.Labels, labelMap) {
			return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
				fmt.Errorf("API_CREATOR is the default label key, please change it")
		}
	}
	loginUser := c.Get("LoginUser")
	if input.Labels == nil {
		input.Labels = map[string]string{
			"API_CREATOR": loginUser.(string),
		}
	} else {
		input.Labels["API_CREATOR"] = loginUser.(string)
	}

	// create
	res, err := h.upstreamStore.Create(c.Context(), input)
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	return res, nil
}

type UpdateInput struct {
	ID string `auto_read:"id,path"`
	entity.Upstream
}

func (h *Handler) Update(c droplet.Context) (interface{}, error) {
	input := c.Input().(*UpdateInput)

	// check if ID in body is equal ID in path
	if err := handler.IDCompare(input.ID, input.Upstream.ID); err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest}, err
	}

	if input.ID != "" {
		input.Upstream.ID = input.ID
	}

	// check creator in Labels
	loginUser := c.Get("LoginUser")
	store, err := h.upstreamStore.Get(c.Context(), input.ID)
	if err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest}, err
	}

	if err := ValidateCreator(loginUser.(string), store.(*entity.Upstream)); err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusForbidden}, err
	}

	_upstream := store.(*entity.Upstream)
	label, ok := _upstream.Labels["API_CREATOR"]
	_, _ok := input.Upstream.Labels["API_CREATOR"]
	if input.Upstream.Labels == nil {
		input.Upstream.Labels = map[string]string{}
	} else if _ok {
		input.Upstream.Labels["API_CREATOR"] = label
	}
	if ok {
		if loginUser != "admin" {
			input.Upstream.Labels["API_CREATOR"] = loginUser.(string)
		} else if loginUser == "admin" {
			input.Upstream.Labels["API_CREATOR"] = label
		}
	}

	// check name existed
	ret, err := handler.NameExistCheck(c.Context(), h.upstreamStore, "upstream", input.Name, input.ID)
	if err != nil {
		return ret, err
	}

	res, err := h.upstreamStore.Update(c.Context(), &input.Upstream, true)
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	return res, nil
}

type BatchDelete struct {
	IDs string `auto_read:"ids,path"`
}

func (h *Handler) BatchDelete(c droplet.Context) (interface{}, error) {
	input := c.Input().(*BatchDelete)

	loginUser := c.Get("LoginUser")
	route, err := h.upstreamStore.Get(c.Context(), input.IDs)
	if err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest}, err
	}

	if err := ValidateCreator(loginUser.(string), route.(*entity.Upstream)); err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusForbidden}, err
	}

	ids := strings.Split(input.IDs, ",")
	mp := make(map[string]struct{})
	for _, id := range ids {
		mp[id] = struct{}{}
	}

	ret, err := h.routeStore.List(c.Context(), store.ListInput{
		Predicate: func(obj interface{}) bool {
			route := obj.(*entity.Route)
			if _, exist := mp[utils.InterfaceToString(route.UpstreamID)]; exist {
				return true
			}

			return false
		},
		PageSize:   0,
		PageNumber: 0,
	})
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	if ret.TotalSize > 0 {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
			fmt.Errorf("route: %s is using this upstream", ret.Rows[0].(*entity.Route).Name)
	}

	ret, err = h.serviceStore.List(c.Context(), store.ListInput{
		Predicate: func(obj interface{}) bool {
			service := obj.(*entity.Service)
			if _, exist := mp[utils.InterfaceToString(service.UpstreamID)]; exist {
				return true
			}

			return false
		},
		PageSize:   0,
		PageNumber: 0,
	})
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	if ret.TotalSize > 0 {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
			fmt.Errorf("service: %s is using this upstream", ret.Rows[0].(*entity.Service).Name)
	}

	if err = h.upstreamStore.BatchDelete(c.Context(), ids); err != nil {
		return handler.SpecCodeResponse(err), err
	}

	return nil, nil
}

type PatchInput struct {
	ID      string `auto_read:"id,path"`
	SubPath string `auto_read:"path,path"`
	Body    []byte `auto_read:"@body"`
}

func (h *Handler) Patch(c droplet.Context) (interface{}, error) {
	input := c.Input().(*PatchInput)
	reqBody := input.Body
	id := input.ID
	subPath := input.SubPath

	stored, err := h.upstreamStore.Get(c.Context(), id)
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	loginUser := c.Get("LoginUser")
	if err := ValidateCreator(loginUser.(string), stored.(*entity.Upstream)); err != nil {
		return &data.SpecCodeResponse{StatusCode: http.StatusForbidden}, err
	}

	res, err := utils.MergePatch(stored, subPath, reqBody)

	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	var upstream entity.Upstream
	if err := json.Unmarshal(res, &upstream); err != nil {
		return handler.SpecCodeResponse(err), err
	}

	_upstream := stored.(*entity.Upstream)
	label, ok := _upstream.Labels["API_CREATOR"]
	_, _ok := upstream.Labels["API_CREATOR"]
	if upstream.Labels == nil {
		upstream.Labels = map[string]string{}
	} else if _ok {
		upstream.Labels["API_CREATOR"] = label
	}
	if ok {
		if loginUser != "admin" {
			upstream.Labels["API_CREATOR"] = loginUser.(string)
		} else if loginUser == "admin" {
			upstream.Labels["API_CREATOR"] = label
		}
	}

	ret, err := h.upstreamStore.Update(c.Context(), &upstream, false)
	if err != nil {
		return handler.SpecCodeResponse(err), err
	}

	return ret, nil
}

type ExistInput struct {
	Name string `auto_read:"name,query"`
}

type ExistCheckInput struct {
	Name    string `auto_read:"name,query"`
	Exclude string `auto_read:"exclude,query"`
}

func (h *Handler) Exist(c droplet.Context) (interface{}, error) {
	input := c.Input().(*ExistCheckInput)
	name := input.Name
	exclude := input.Exclude

	ret, err := h.upstreamStore.List(c.Context(), store.ListInput{
		Predicate: func(obj interface{}) bool {
			r := obj.(*entity.Upstream)
			if r.Name == name && r.ID != exclude {
				return true
			}
			return false
		},
		PageSize:   0,
		PageNumber: 0,
	})

	if err != nil {
		return nil, err
	}

	if ret.TotalSize > 0 {
		return &data.SpecCodeResponse{StatusCode: http.StatusBadRequest},
			consts.InvalidParam("Upstream name is reduplicate")
	}
	return nil, nil
}

func (h *Handler) listUpstreamNames(c droplet.Context) (interface{}, error) {
	ret, err := h.upstreamStore.List(c.Context(), store.ListInput{
		Predicate:  nil,
		PageSize:   0,
		PageNumber: 0,
	})

	if err != nil {
		return nil, err
	}

	rows := make([]interface{}, ret.TotalSize)
	for i := range ret.Rows {
		row := ret.Rows[i].(*entity.Upstream)
		rows[i], _ = row.Parse2NameResponse()
	}

	output := &store.ListOutput{
		Rows:      rows,
		TotalSize: ret.TotalSize,
	}

	return output, nil
}

// validate: loginuser match with creator
func ValidateCreator(loginUser string, upstream *entity.Upstream) error {
	creator, _ := upstream.Labels["API_CREATOR"]
	if loginUser != "admin" && loginUser != creator {
		return fmt.Errorf("Permission denied: \"API_CREATOR:%s\" not match with login user %s", creator, loginUser)
	}
	return nil
}