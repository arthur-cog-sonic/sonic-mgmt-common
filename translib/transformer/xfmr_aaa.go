////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2024 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");          //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,        //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	"fmt"
	"strings"

	log "github.com/golang/glog"
)

func init() {
	XlateFuncBind("aaa_tbl_key_xfmr", aaa_tbl_key_xfmr)
	XlateFuncBind("YangToDb_aaa_auth_method_xfmr", YangToDb_aaa_auth_method_xfmr)
	XlateFuncBind("DbToYang_aaa_auth_method_xfmr", DbToYang_aaa_auth_method_xfmr)
	XlateFuncBind("YangToDb_aaa_authz_method_xfmr", YangToDb_aaa_authz_method_xfmr)
	XlateFuncBind("DbToYang_aaa_authz_method_xfmr", DbToYang_aaa_authz_method_xfmr)
	XlateFuncBind("YangToDb_aaa_acct_method_xfmr", YangToDb_aaa_acct_method_xfmr)
	XlateFuncBind("DbToYang_aaa_acct_method_xfmr", DbToYang_aaa_acct_method_xfmr)
}

var aaa_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	log.Info("aaa_tbl_key_xfmr: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)
	uriPath := pathInfo.Template

	if strings.Contains(uriPath, "authorization") {
		return "authorization", nil
	} else if strings.Contains(uriPath, "accounting") {
		return "accounting", nil
	}
	return "authentication", nil
}

func aaaMethodListToLoginString(methods []interface{}) string {
	var parts []string
	for _, m := range methods {
		s := fmt.Sprintf("%v", m)
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ",")
}

func aaaLoginStringToMethodList(loginStr string) []string {
	var methods []string
	if loginStr == "" {
		return methods
	}
	parts := strings.Split(loginStr, ",")
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			methods = append(methods, trimmed)
		}
	}
	return methods
}

var YangToDb_aaa_auth_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	log.Info("YangToDb_aaa_auth_method_xfmr: ", inParams.param)

	if inParams.param == nil {
		return res_map, nil
	}

	methods, ok := inParams.param.([]interface{})
	if ok && len(methods) > 0 {
		res_map["login"] = aaaMethodListToLoginString(methods)
	} else {
		s := fmt.Sprintf("%v", inParams.param)
		if s != "" {
			res_map["login"] = s
		}
	}
	return res_map, nil
}

var DbToYang_aaa_auth_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	log.Info("DbToYang_aaa_auth_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	aaaEntry, ok := data["AAA"]
	if !ok {
		return result, nil
	}
	entry, ok := aaaEntry["authentication"]
	if !ok {
		return result, nil
	}

	loginStr := entry.Get("login")
	methods := aaaLoginStringToMethodList(loginStr)
	if len(methods) > 0 {
		result["authentication-method"] = methods
	}
	return result, nil
}

var YangToDb_aaa_authz_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	log.Info("YangToDb_aaa_authz_method_xfmr: ", inParams.param)

	if inParams.param == nil {
		return res_map, nil
	}

	methods, ok := inParams.param.([]interface{})
	if ok && len(methods) > 0 {
		res_map["login"] = aaaMethodListToLoginString(methods)
	} else {
		s := fmt.Sprintf("%v", inParams.param)
		if s != "" {
			res_map["login"] = s
		}
	}
	return res_map, nil
}

var DbToYang_aaa_authz_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	log.Info("DbToYang_aaa_authz_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	aaaEntry, ok := data["AAA"]
	if !ok {
		return result, nil
	}
	entry, ok := aaaEntry["authorization"]
	if !ok {
		return result, nil
	}

	loginStr := entry.Get("login")
	methods := aaaLoginStringToMethodList(loginStr)
	if len(methods) > 0 {
		result["authorization-method"] = methods
	}
	return result, nil
}

var YangToDb_aaa_acct_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	log.Info("YangToDb_aaa_acct_method_xfmr: ", inParams.param)

	if inParams.param == nil {
		return res_map, nil
	}

	methods, ok := inParams.param.([]interface{})
	if ok && len(methods) > 0 {
		res_map["login"] = aaaMethodListToLoginString(methods)
	} else {
		s := fmt.Sprintf("%v", inParams.param)
		if s != "" {
			res_map["login"] = s
		}
	}
	return res_map, nil
}

var DbToYang_aaa_acct_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	log.Info("DbToYang_aaa_acct_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	aaaEntry, ok := data["AAA"]
	if !ok {
		return result, nil
	}
	entry, ok := aaaEntry["accounting"]
	if !ok {
		return result, nil
	}

	loginStr := entry.Get("login")
	methods := aaaLoginStringToMethodList(loginStr)
	if len(methods) > 0 {
		result["accounting-method"] = methods
	}
	return result, nil
}
