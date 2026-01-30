////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2024 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
// its subsidiaries.                                                          //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

const (
	AAA_TABLE              = "AAA"
	AAA_AUTHENTICATION_KEY = "authentication"
	AAA_AUTHORIZATION_KEY  = "authorization"
	AAA_ACCOUNTING_KEY     = "accounting"

	AAA_LOGIN_FIELD       = "login"
	AAA_FAILTHROUGH_FIELD = "failthrough"
	AAA_FALLBACK_FIELD    = "fallback"
	AAA_DEBUG_FIELD       = "debug"
	AAA_TRACE_FIELD       = "trace"

	AAA_URI                    = "/openconfig-system:system/aaa"
	AAA_AUTHENTICATION_URI     = "/openconfig-system:system/aaa/authentication"
	AAA_AUTHENTICATION_CFG_URI = "/openconfig-system:system/aaa/authentication/config"
	AAA_AUTHORIZATION_URI      = "/openconfig-system:system/aaa/authorization"
	AAA_AUTHORIZATION_CFG_URI  = "/openconfig-system:system/aaa/authorization/config"
	AAA_ACCOUNTING_URI         = "/openconfig-system:system/aaa/accounting"
	AAA_ACCOUNTING_CFG_URI     = "/openconfig-system:system/aaa/accounting/config"
)

func init() {
	XlateFuncBind("aaa_subtree_xfmr", aaa_subtree_xfmr)
	XlateFuncBind("YangToDb_aaa_subtree_xfmr", YangToDb_aaa_subtree_xfmr)
	XlateFuncBind("DbToYang_aaa_subtree_xfmr", DbToYang_aaa_subtree_xfmr)
	XlateFuncBind("aaa_authentication_key_xfmr", aaa_authentication_key_xfmr)
	XlateFuncBind("aaa_authorization_key_xfmr", aaa_authorization_key_xfmr)
	XlateFuncBind("aaa_accounting_key_xfmr", aaa_accounting_key_xfmr)
	XlateFuncBind("YangToDb_aaa_auth_method_xfmr", YangToDb_aaa_auth_method_xfmr)
	XlateFuncBind("DbToYang_aaa_auth_method_xfmr", DbToYang_aaa_auth_method_xfmr)
	XlateFuncBind("YangToDb_aaa_authz_method_xfmr", YangToDb_aaa_authz_method_xfmr)
	XlateFuncBind("DbToYang_aaa_authz_method_xfmr", DbToYang_aaa_authz_method_xfmr)
	XlateFuncBind("YangToDb_aaa_acct_method_xfmr", YangToDb_aaa_acct_method_xfmr)
	XlateFuncBind("DbToYang_aaa_acct_method_xfmr", DbToYang_aaa_acct_method_xfmr)
}

func getAaaRoot(s *ygot.GoStruct) *ocbinds.OpenconfigSystem_System_Aaa {
	deviceObj := (*s).(*ocbinds.Device)
	if deviceObj.System == nil {
		return nil
	}
	return deviceObj.System.Aaa
}

func extractAuthMethodString(m ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union) string {
	switch v := m.(type) {
	case *ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE:
		return methodTypeToString(v.E_OpenconfigAaaTypes_AAA_METHOD_TYPE)
	case *ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_String:
		return v.String
	default:
		return ""
	}
}

func extractAuthzMethodString(m ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union) string {
	switch v := m.(type) {
	case *ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE:
		return methodTypeToString(v.E_OpenconfigAaaTypes_AAA_METHOD_TYPE)
	case *ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_String:
		return v.String
	default:
		return ""
	}
}

func extractAcctMethodString(m ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union) string {
	switch v := m.(type) {
	case *ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE:
		return methodTypeToString(v.E_OpenconfigAaaTypes_AAA_METHOD_TYPE)
	case *ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_String:
		return v.String
	default:
		return ""
	}
}

var aaa_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	return YangToDb_aaa_subtree_xfmr(inParams)
}

var YangToDb_aaa_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	res_map := make(map[string]map[string]db.Value)
	aaa_map := make(map[string]db.Value)

	log.Info("YangToDb_aaa_subtree_xfmr: ", inParams.uri)

	aaaObj := getAaaRoot(inParams.ygRoot)
	if aaaObj == nil {
		log.Info("YangToDb_aaa_subtree_xfmr: AAA object is nil")
		return res_map, err
	}

	targetUriPath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

	if inParams.oper == DELETE {
		return handleAaaDelete(targetUriPath, aaa_map, res_map)
	}

	if aaaObj.Authentication != nil && aaaObj.Authentication.Config != nil {
		aaa_map[AAA_AUTHENTICATION_KEY] = db.Value{Field: make(map[string]string)}

		if aaaObj.Authentication.Config.AuthenticationMethod != nil {
			methods := aaaObj.Authentication.Config.AuthenticationMethod
			methodStrs := make([]string, 0, len(methods))
			for _, m := range methods {
				mStr := extractAuthMethodString(m)
				if mStr != "" {
					methodStrs = append(methodStrs, mStr)
				}
			}
			if len(methodStrs) > 0 {
				aaa_map[AAA_AUTHENTICATION_KEY].Field[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
			}
		}
	}

	if aaaObj.Authorization != nil && aaaObj.Authorization.Config != nil {
		aaa_map[AAA_AUTHORIZATION_KEY] = db.Value{Field: make(map[string]string)}

		if aaaObj.Authorization.Config.AuthorizationMethod != nil {
			methods := aaaObj.Authorization.Config.AuthorizationMethod
			methodStrs := make([]string, 0, len(methods))
			for _, m := range methods {
				mStr := extractAuthzMethodString(m)
				if mStr != "" {
					methodStrs = append(methodStrs, mStr)
				}
			}
			if len(methodStrs) > 0 {
				aaa_map[AAA_AUTHORIZATION_KEY].Field[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
			}
		}
	}

	if aaaObj.Accounting != nil && aaaObj.Accounting.Config != nil {
		aaa_map[AAA_ACCOUNTING_KEY] = db.Value{Field: make(map[string]string)}

		if aaaObj.Accounting.Config.AccountingMethod != nil {
			methods := aaaObj.Accounting.Config.AccountingMethod
			methodStrs := make([]string, 0, len(methods))
			for _, m := range methods {
				mStr := extractAcctMethodString(m)
				if mStr != "" {
					methodStrs = append(methodStrs, mStr)
				}
			}
			if len(methodStrs) > 0 {
				aaa_map[AAA_ACCOUNTING_KEY].Field[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
			}
		}
	}

	if len(aaa_map) > 0 {
		res_map[AAA_TABLE] = aaa_map
	}

	return res_map, err
}

func handleAaaDelete(targetUriPath string, aaa_map map[string]db.Value, res_map map[string]map[string]db.Value) (map[string]map[string]db.Value, error) {
	var err error

	switch {
	case strings.Contains(targetUriPath, "authentication/config/authentication-method"):
		aaa_map[AAA_AUTHENTICATION_KEY] = db.Value{Field: make(map[string]string)}
		aaa_map[AAA_AUTHENTICATION_KEY].Field[AAA_LOGIN_FIELD] = ""
	case strings.Contains(targetUriPath, "authorization/config/authorization-method"):
		aaa_map[AAA_AUTHORIZATION_KEY] = db.Value{Field: make(map[string]string)}
		aaa_map[AAA_AUTHORIZATION_KEY].Field[AAA_LOGIN_FIELD] = ""
	case strings.Contains(targetUriPath, "accounting/config/accounting-method"):
		aaa_map[AAA_ACCOUNTING_KEY] = db.Value{Field: make(map[string]string)}
		aaa_map[AAA_ACCOUNTING_KEY].Field[AAA_LOGIN_FIELD] = ""
	}

	if len(aaa_map) > 0 {
		res_map[AAA_TABLE] = aaa_map
	}

	return res_map, err
}

func methodTypeToString(method ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE) string {
	switch method {
	case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL:
		return "local"
	case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL:
		return "tacacs+"
	case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL:
		return "radius"
	default:
		return ""
	}
}

func stringToMethodType(method string) ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE {
	switch strings.ToLower(method) {
	case "local":
		return ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL
	case "tacacs+":
		return ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL
	case "radius":
		return ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL
	default:
		return ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET
	}
}

var DbToYang_aaa_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	log.Info("DbToYang_aaa_subtree_xfmr: ", inParams.uri)

	aaaObj := getAaaRoot(inParams.ygRoot)
	if aaaObj == nil {
		log.Info("DbToYang_aaa_subtree_xfmr: AAA object is nil, building empty tree")
		deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
		if deviceObj.System == nil {
			ygot.BuildEmptyTree(deviceObj)
		}
		if deviceObj.System.Aaa == nil {
			ygot.BuildEmptyTree(deviceObj.System)
		}
		aaaObj = deviceObj.System.Aaa
	}

	ygot.BuildEmptyTree(aaaObj)

	cfgDb := inParams.dbs[db.ConfigDB]

	authEntry, err := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TABLE}, db.Key{Comp: []string{AAA_AUTHENTICATION_KEY}})
	if err == nil && authEntry.IsPopulated() {
		if aaaObj.Authentication == nil {
			ygot.BuildEmptyTree(aaaObj)
		}
		if aaaObj.Authentication.Config == nil {
			ygot.BuildEmptyTree(aaaObj.Authentication)
		}
		if aaaObj.Authentication.State == nil {
			ygot.BuildEmptyTree(aaaObj.Authentication)
		}

		if login := authEntry.Get(AAA_LOGIN_FIELD); login != "" {
			methods := strings.Split(login, ",")
			configMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union, 0, len(methods))
			stateMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Authentication_State_AuthenticationMethod_Union, 0, len(methods))
			for _, m := range methods {
				methodType := stringToMethodType(m)
				if methodType != ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET {
					configMethodList = append(configMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
					stateMethodList = append(stateMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Authentication_State_AuthenticationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
				}
			}
			aaaObj.Authentication.Config.AuthenticationMethod = configMethodList
			aaaObj.Authentication.State.AuthenticationMethod = stateMethodList
		}
	}

	authzEntry, err := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TABLE}, db.Key{Comp: []string{AAA_AUTHORIZATION_KEY}})
	if err == nil && authzEntry.IsPopulated() {
		if aaaObj.Authorization == nil {
			ygot.BuildEmptyTree(aaaObj)
		}
		if aaaObj.Authorization.Config == nil {
			ygot.BuildEmptyTree(aaaObj.Authorization)
		}
		if aaaObj.Authorization.State == nil {
			ygot.BuildEmptyTree(aaaObj.Authorization)
		}

		if login := authzEntry.Get(AAA_LOGIN_FIELD); login != "" {
			methods := strings.Split(login, ",")
			configMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union, 0, len(methods))
			stateMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Authorization_State_AuthorizationMethod_Union, 0, len(methods))
			for _, m := range methods {
				methodType := stringToMethodType(m)
				if methodType != ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET {
					configMethodList = append(configMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
					stateMethodList = append(stateMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Authorization_State_AuthorizationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
				}
			}
			aaaObj.Authorization.Config.AuthorizationMethod = configMethodList
			aaaObj.Authorization.State.AuthorizationMethod = stateMethodList
		}
	}

	acctEntry, err := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TABLE}, db.Key{Comp: []string{AAA_ACCOUNTING_KEY}})
	if err == nil && acctEntry.IsPopulated() {
		if aaaObj.Accounting == nil {
			ygot.BuildEmptyTree(aaaObj)
		}
		if aaaObj.Accounting.Config == nil {
			ygot.BuildEmptyTree(aaaObj.Accounting)
		}
		if aaaObj.Accounting.State == nil {
			ygot.BuildEmptyTree(aaaObj.Accounting)
		}

		if login := acctEntry.Get(AAA_LOGIN_FIELD); login != "" {
			methods := strings.Split(login, ",")
			configMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union, 0, len(methods))
			stateMethodList := make([]ocbinds.OpenconfigSystem_System_Aaa_Accounting_State_AccountingMethod_Union, 0, len(methods))
			for _, m := range methods {
				methodType := stringToMethodType(m)
				if methodType != ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET {
					configMethodList = append(configMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
					stateMethodList = append(stateMethodList, &ocbinds.OpenconfigSystem_System_Aaa_Accounting_State_AccountingMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
						E_OpenconfigAaaTypes_AAA_METHOD_TYPE: methodType,
					})
				}
			}
			aaaObj.Accounting.Config.AccountingMethod = configMethodList
			aaaObj.Accounting.State.AccountingMethod = stateMethodList
		}
	}

	return nil
}

var aaa_authentication_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	log.Info("aaa_authentication_key_xfmr: ", inParams.key)
	return AAA_AUTHENTICATION_KEY, nil
}

var aaa_authorization_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	log.Info("aaa_authorization_key_xfmr: ", inParams.key)
	return AAA_AUTHORIZATION_KEY, nil
}

var aaa_accounting_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	log.Info("aaa_accounting_key_xfmr: ", inParams.key)
	return AAA_ACCOUNTING_KEY, nil
}

var YangToDb_aaa_auth_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_aaa_auth_method_xfmr: ", inParams.param)

	if methods, ok := inParams.param.([]interface{}); ok {
		methodStrs := make([]string, 0, len(methods))
		for _, m := range methods {
			if mStr, ok := m.(string); ok {
				methodStrs = append(methodStrs, mStr)
			}
		}
		if len(methodStrs) > 0 {
			res_map[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
		}
	}

	return res_map, err
}

var DbToYang_aaa_auth_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var err error
	log.Info("DbToYang_aaa_auth_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	if aaaData, ok := data[AAA_TABLE]; ok {
		if authData, ok := aaaData[AAA_AUTHENTICATION_KEY]; ok {
			if login := authData.Get(AAA_LOGIN_FIELD); login != "" {
				methods := strings.Split(login, ",")
				result["authentication-method"] = methods
			}
		}
	}

	return result, err
}

var YangToDb_aaa_authz_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_aaa_authz_method_xfmr: ", inParams.param)

	if methods, ok := inParams.param.([]interface{}); ok {
		methodStrs := make([]string, 0, len(methods))
		for _, m := range methods {
			if mStr, ok := m.(string); ok {
				methodStrs = append(methodStrs, mStr)
			}
		}
		if len(methodStrs) > 0 {
			res_map[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
		}
	}

	return res_map, err
}

var DbToYang_aaa_authz_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var err error
	log.Info("DbToYang_aaa_authz_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	if aaaData, ok := data[AAA_TABLE]; ok {
		if authzData, ok := aaaData[AAA_AUTHORIZATION_KEY]; ok {
			if login := authzData.Get(AAA_LOGIN_FIELD); login != "" {
				methods := strings.Split(login, ",")
				result["authorization-method"] = methods
			}
		}
	}

	return result, err
}

var YangToDb_aaa_acct_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_aaa_acct_method_xfmr: ", inParams.param)

	if methods, ok := inParams.param.([]interface{}); ok {
		methodStrs := make([]string, 0, len(methods))
		for _, m := range methods {
			if mStr, ok := m.(string); ok {
				methodStrs = append(methodStrs, mStr)
			}
		}
		if len(methodStrs) > 0 {
			res_map[AAA_LOGIN_FIELD] = strings.Join(methodStrs, ",")
		}
	}

	return res_map, err
}

var DbToYang_aaa_acct_method_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var err error
	log.Info("DbToYang_aaa_acct_method_xfmr: ", inParams.key)

	data := (*inParams.dbDataMap)[inParams.curDb]
	if aaaData, ok := data[AAA_TABLE]; ok {
		if acctData, ok := aaaData[AAA_ACCOUNTING_KEY]; ok {
			if login := acctData.Get(AAA_LOGIN_FIELD); login != "" {
				methods := strings.Split(login, ",")
				result["accounting-method"] = methods
			}
		}
	}

	return result, err
}
