////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2024 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.           //
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
	"errors"
	"reflect"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

const (
	AAA_TBL             = "AAA"
	AAA_AUTH_KEY        = "authentication"
	AAA_AUTHZ_KEY       = "authorization"
	AAA_ACCT_KEY        = "accounting"
	AAA_LOGIN_FLD       = "login"
	AAA_FAILTHROUGH_FLD = "failthrough"
	AAA_FALLBACK_FLD    = "fallback"
	AAA_DEBUG_FLD       = "debug"

	AAA_URI                 = "/openconfig-system:system/aaa"
	AAA_AUTH                = "/openconfig-system:system/aaa/authentication"
	AAA_AUTH_CONFIG         = "/openconfig-system:system/aaa/authentication/config"
	AAA_AUTH_CONFIG_METHOD  = "/openconfig-system:system/aaa/authentication/config/authentication-method"
	AAA_AUTH_STATE          = "/openconfig-system:system/aaa/authentication/state"
	AAA_AUTHZ               = "/openconfig-system:system/aaa/authorization"
	AAA_AUTHZ_CONFIG        = "/openconfig-system:system/aaa/authorization/config"
	AAA_AUTHZ_CONFIG_METHOD = "/openconfig-system:system/aaa/authorization/config/authorization-method"
	AAA_AUTHZ_STATE         = "/openconfig-system:system/aaa/authorization/state"
	AAA_ACCT                = "/openconfig-system:system/aaa/accounting"
	AAA_ACCT_CONFIG         = "/openconfig-system:system/aaa/accounting/config"
	AAA_ACCT_CONFIG_METHOD  = "/openconfig-system:system/aaa/accounting/config/accounting-method"
	AAA_ACCT_STATE          = "/openconfig-system:system/aaa/accounting/state"
)

func init() {
	XlateFuncBind("YangToDb_aaa_subtree_xfmr", YangToDb_aaa_subtree_xfmr)
	XlateFuncBind("DbToYang_aaa_subtree_xfmr", DbToYang_aaa_subtree_xfmr)
}

func getAaaSystemRoot(s *ygot.GoStruct) *ocbinds.OpenconfigSystem_System {
	deviceObj := (*s).(*ocbinds.Device)
	if deviceObj == nil {
		return nil
	}
	return deviceObj.System
}

func aaaBoolToStr(val bool) string {
	if val {
		return "True"
	}
	return "False"
}

func aaaStrToBool(val string) bool {
	return strings.EqualFold(val, "true")
}

func aaaAuthMethodUnionToStr(method ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union) string {
	unionType := reflect.TypeOf(method).Elem()
	switch unionType {
	case reflect.TypeOf(ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_String{}):
		val := method.(*ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_String)
		return val.String
	default:
		log.Warningf("aaaAuthMethodUnionToStr: unhandled union type %v", unionType)
		return ""
	}
}

func aaaAuthzMethodUnionToStr(method ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union) string {
	unionType := reflect.TypeOf(method).Elem()
	switch unionType {
	case reflect.TypeOf(ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_String{}):
		val := method.(*ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_String)
		return val.String
	default:
		log.Warningf("aaaAuthzMethodUnionToStr: unhandled union type %v", unionType)
		return ""
	}
}

func aaaAcctMethodUnionToStr(method ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union) string {
	unionType := reflect.TypeOf(method).Elem()
	switch unionType {
	case reflect.TypeOf(ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_String{}):
		val := method.(*ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_String)
		return val.String
	default:
		log.Warningf("aaaAcctMethodUnionToStr: unhandled union type %v", unionType)
		return ""
	}
}

func aaaLoginStrToMethodList(login string) []string {
	var methods []string
	if login == "" {
		return methods
	}
	for _, m := range strings.Split(login, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}

var YangToDb_aaa_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	res_map := make(map[string]map[string]db.Value)
	aaa_map := make(map[string]db.Value)

	log.Info("YangToDb_aaa_subtree_xfmr: uri=", inParams.uri)
	targetUriPath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

	if inParams.oper == DELETE {
		switch {
		case strings.HasPrefix(targetUriPath, AAA_AUTH_CONFIG_METHOD):
			aaa_map[AAA_AUTH_KEY] = db.Value{Field: map[string]string{AAA_LOGIN_FLD: ""}}
		case strings.HasPrefix(targetUriPath, AAA_AUTH_CONFIG):
			aaa_map[AAA_AUTH_KEY] = db.Value{Field: make(map[string]string)}
		case strings.HasPrefix(targetUriPath, AAA_AUTH):
			aaa_map[AAA_AUTH_KEY] = db.Value{Field: make(map[string]string)}
		case strings.HasPrefix(targetUriPath, AAA_AUTHZ_CONFIG_METHOD):
			aaa_map[AAA_AUTHZ_KEY] = db.Value{Field: map[string]string{AAA_LOGIN_FLD: ""}}
		case strings.HasPrefix(targetUriPath, AAA_AUTHZ_CONFIG):
			aaa_map[AAA_AUTHZ_KEY] = db.Value{Field: make(map[string]string)}
		case strings.HasPrefix(targetUriPath, AAA_AUTHZ):
			aaa_map[AAA_AUTHZ_KEY] = db.Value{Field: make(map[string]string)}
		case strings.HasPrefix(targetUriPath, AAA_ACCT_CONFIG_METHOD):
			aaa_map[AAA_ACCT_KEY] = db.Value{Field: map[string]string{AAA_LOGIN_FLD: ""}}
		case strings.HasPrefix(targetUriPath, AAA_ACCT_CONFIG):
			aaa_map[AAA_ACCT_KEY] = db.Value{Field: make(map[string]string)}
		case strings.HasPrefix(targetUriPath, AAA_ACCT):
			aaa_map[AAA_ACCT_KEY] = db.Value{Field: make(map[string]string)}
		default:
			return res_map, errors.New("DELETE not supported on this path")
		}
		res_map[AAA_TBL] = aaa_map
		return res_map, err
	}

	sysObj := getAaaSystemRoot(inParams.ygRoot)
	if sysObj == nil || sysObj.Aaa == nil {
		log.Info("YangToDb_aaa_subtree_xfmr: no AAA data in ygRoot")
		return res_map, err
	}

	aaaObj := sysObj.Aaa

	if aaaObj.Authentication != nil && aaaObj.Authentication.Config != nil {
		authConfig := aaaObj.Authentication.Config
		aaa_map[AAA_AUTH_KEY] = db.Value{Field: make(map[string]string)}

		if len(authConfig.AuthenticationMethod) > 0 {
			var parts []string
			for _, m := range authConfig.AuthenticationMethod {
				s := aaaAuthMethodUnionToStr(m)
				if s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				aaa_map[AAA_AUTH_KEY].Field[AAA_LOGIN_FLD] = strings.Join(parts, ",")
			}
		}

		if authConfig.Failthrough != nil {
			aaa_map[AAA_AUTH_KEY].Field[AAA_FAILTHROUGH_FLD] = aaaBoolToStr(*authConfig.Failthrough)
		}
		if authConfig.Fallback != nil {
			aaa_map[AAA_AUTH_KEY].Field[AAA_FALLBACK_FLD] = aaaBoolToStr(*authConfig.Fallback)
		}
		if authConfig.Debug != nil {
			aaa_map[AAA_AUTH_KEY].Field[AAA_DEBUG_FLD] = aaaBoolToStr(*authConfig.Debug)
		}
	}

	if aaaObj.Authorization != nil && aaaObj.Authorization.Config != nil {
		authzConfig := aaaObj.Authorization.Config
		aaa_map[AAA_AUTHZ_KEY] = db.Value{Field: make(map[string]string)}

		if len(authzConfig.AuthorizationMethod) > 0 {
			var parts []string
			for _, m := range authzConfig.AuthorizationMethod {
				s := aaaAuthzMethodUnionToStr(m)
				if s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				aaa_map[AAA_AUTHZ_KEY].Field[AAA_LOGIN_FLD] = strings.Join(parts, ",")
			}
		}
	}

	if aaaObj.Accounting != nil && aaaObj.Accounting.Config != nil {
		acctConfig := aaaObj.Accounting.Config
		aaa_map[AAA_ACCT_KEY] = db.Value{Field: make(map[string]string)}

		if len(acctConfig.AccountingMethod) > 0 {
			var parts []string
			for _, m := range acctConfig.AccountingMethod {
				s := aaaAcctMethodUnionToStr(m)
				if s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				aaa_map[AAA_ACCT_KEY].Field[AAA_LOGIN_FLD] = strings.Join(parts, ",")
			}
		}
	}

	if len(aaa_map) > 0 {
		res_map[AAA_TBL] = aaa_map
	}
	return res_map, err
}

var DbToYang_aaa_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	log.Info("DbToYang_aaa_subtree_xfmr: uri=", inParams.uri)
	targetUriPath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

	sysObj := getAaaSystemRoot(inParams.ygRoot)
	if sysObj == nil {
		return errors.New("system root object is nil")
	}

	ygot.BuildEmptyTree(sysObj)
	if sysObj.Aaa == nil {
		ygot.BuildEmptyTree(sysObj)
	}
	ygot.BuildEmptyTree(sysObj.Aaa)
	ygot.BuildEmptyTree(sysObj.Aaa.Authentication)
	ygot.BuildEmptyTree(sysObj.Aaa.Authentication.Config)
	ygot.BuildEmptyTree(sysObj.Aaa.Authentication.State)
	ygot.BuildEmptyTree(sysObj.Aaa.Authorization)
	ygot.BuildEmptyTree(sysObj.Aaa.Authorization.Config)
	ygot.BuildEmptyTree(sysObj.Aaa.Authorization.State)
	ygot.BuildEmptyTree(sysObj.Aaa.Accounting)
	ygot.BuildEmptyTree(sysObj.Aaa.Accounting.Config)
	ygot.BuildEmptyTree(sysObj.Aaa.Accounting.State)

	cfgDb := inParams.dbs[db.ConfigDB]

	authEntry, authErr := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TBL}, db.Key{Comp: []string{AAA_AUTH_KEY}})
	authzEntry, authzErr := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TBL}, db.Key{Comp: []string{AAA_AUTHZ_KEY}})
	acctEntry, acctErr := cfgDb.GetEntry(&db.TableSpec{Name: AAA_TBL}, db.Key{Comp: []string{AAA_ACCT_KEY}})

	switch {
	case strings.HasPrefix(targetUriPath, AAA_AUTH_CONFIG) || strings.HasPrefix(targetUriPath, AAA_AUTH_STATE) || strings.HasPrefix(targetUriPath, AAA_AUTH):
		if authErr == nil {
			fillAaaAuthData(sysObj, authEntry.Field)
		}
	case strings.HasPrefix(targetUriPath, AAA_AUTHZ_CONFIG) || strings.HasPrefix(targetUriPath, AAA_AUTHZ_STATE) || strings.HasPrefix(targetUriPath, AAA_AUTHZ):
		if authzErr == nil {
			fillAaaAuthzData(sysObj, authzEntry.Field)
		}
	case strings.HasPrefix(targetUriPath, AAA_ACCT_CONFIG) || strings.HasPrefix(targetUriPath, AAA_ACCT_STATE) || strings.HasPrefix(targetUriPath, AAA_ACCT):
		if acctErr == nil {
			fillAaaAcctData(sysObj, acctEntry.Field)
		}
	default:
		if authErr == nil {
			fillAaaAuthData(sysObj, authEntry.Field)
		}
		if authzErr == nil {
			fillAaaAuthzData(sysObj, authzEntry.Field)
		}
		if acctErr == nil {
			fillAaaAcctData(sysObj, acctEntry.Field)
		}
	}

	return nil
}

func fillAaaAuthData(sysObj *ocbinds.OpenconfigSystem_System, fields map[string]string) {
	if sysObj.Aaa == nil || sysObj.Aaa.Authentication == nil {
		return
	}

	if login, ok := fields[AAA_LOGIN_FLD]; ok && login != "" {
		methods := aaaLoginStrToMethodList(login)
		for _, m := range methods {
			cfgMethod, cfgErr := sysObj.Aaa.Authentication.Config.To_OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union(m)
			if cfgErr == nil {
				sysObj.Aaa.Authentication.Config.AuthenticationMethod = append(
					sysObj.Aaa.Authentication.Config.AuthenticationMethod, cfgMethod)
			}
			stMethod, stErr := sysObj.Aaa.Authentication.State.To_OpenconfigSystem_System_Aaa_Authentication_State_AuthenticationMethod_Union(m)
			if stErr == nil {
				sysObj.Aaa.Authentication.State.AuthenticationMethod = append(
					sysObj.Aaa.Authentication.State.AuthenticationMethod, stMethod)
			}
		}
	}

	if ft, ok := fields[AAA_FAILTHROUGH_FLD]; ok {
		ftVal := aaaStrToBool(ft)
		sysObj.Aaa.Authentication.Config.Failthrough = &ftVal
		sysObj.Aaa.Authentication.State.Failthrough = &ftVal
	}

	if fb, ok := fields[AAA_FALLBACK_FLD]; ok {
		fbVal := aaaStrToBool(fb)
		sysObj.Aaa.Authentication.Config.Fallback = &fbVal
		sysObj.Aaa.Authentication.State.Fallback = &fbVal
	}

	if dbg, ok := fields[AAA_DEBUG_FLD]; ok {
		dbgVal := aaaStrToBool(dbg)
		sysObj.Aaa.Authentication.Config.Debug = &dbgVal
		sysObj.Aaa.Authentication.State.Debug = &dbgVal
	}
}

func fillAaaAuthzData(sysObj *ocbinds.OpenconfigSystem_System, fields map[string]string) {
	if sysObj.Aaa == nil || sysObj.Aaa.Authorization == nil {
		return
	}

	if login, ok := fields[AAA_LOGIN_FLD]; ok && login != "" {
		methods := aaaLoginStrToMethodList(login)
		for _, m := range methods {
			cfgMethod, cfgErr := sysObj.Aaa.Authorization.Config.To_OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union(m)
			if cfgErr == nil {
				sysObj.Aaa.Authorization.Config.AuthorizationMethod = append(
					sysObj.Aaa.Authorization.Config.AuthorizationMethod, cfgMethod)
			}
			stMethod, stErr := sysObj.Aaa.Authorization.State.To_OpenconfigSystem_System_Aaa_Authorization_State_AuthorizationMethod_Union(m)
			if stErr == nil {
				sysObj.Aaa.Authorization.State.AuthorizationMethod = append(
					sysObj.Aaa.Authorization.State.AuthorizationMethod, stMethod)
			}
		}
	}
}

func fillAaaAcctData(sysObj *ocbinds.OpenconfigSystem_System, fields map[string]string) {
	if sysObj.Aaa == nil || sysObj.Aaa.Accounting == nil {
		return
	}

	if login, ok := fields[AAA_LOGIN_FLD]; ok && login != "" {
		methods := aaaLoginStrToMethodList(login)
		for _, m := range methods {
			cfgMethod, cfgErr := sysObj.Aaa.Accounting.Config.To_OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union(m)
			if cfgErr == nil {
				sysObj.Aaa.Accounting.Config.AccountingMethod = append(
					sysObj.Aaa.Accounting.Config.AccountingMethod, cfgMethod)
			}
			stMethod, stErr := sysObj.Aaa.Accounting.State.To_OpenconfigSystem_System_Aaa_Accounting_State_AccountingMethod_Union(m)
			if stErr == nil {
				sysObj.Aaa.Accounting.State.AccountingMethod = append(
					sysObj.Aaa.Accounting.State.AccountingMethod, stMethod)
			}
		}
	}
}
