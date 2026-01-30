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
	"reflect"
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
)

func TestMethodTypeToString(t *testing.T) {
	tests := []struct {
		name     string
		method   ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE
		expected string
	}{
		{"LOCAL method", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL, "local"},
		{"TACACS_ALL method", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL, "tacacs+"},
		{"RADIUS_ALL method", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL, "radius"},
		{"UNSET method", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET, ""},
		{"Unknown method value", ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE(999), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := methodTypeToString(tt.method)
			if result != tt.expected {
				t.Errorf("methodTypeToString(%v) = %v, want %v", tt.method, result, tt.expected)
			}
		})
	}
}

func TestStringToMethodType(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE
	}{
		{"local lowercase", "local", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL},
		{"LOCAL uppercase", "LOCAL", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL},
		{"tacacs+ lowercase", "tacacs+", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL},
		{"TACACS+ uppercase", "TACACS+", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL},
		{"radius lowercase", "radius", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL},
		{"RADIUS uppercase", "RADIUS", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL},
		{"unknown method", "unknown", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET},
		{"empty string", "", ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringToMethodType(tt.method)
			if result != tt.expected {
				t.Errorf("stringToMethodType(%v) = %v, want %v", tt.method, result, tt.expected)
			}
		})
	}
}

func TestExtractAuthMethodString(t *testing.T) {
	tests := []struct {
		name     string
		method   ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union
		expected string
	}{
		{
			"LOCAL enum type",
			&ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
				E_OpenconfigAaaTypes_AAA_METHOD_TYPE: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
			},
			"local",
		},
		{
			"TACACS_ALL enum type",
			&ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
				E_OpenconfigAaaTypes_AAA_METHOD_TYPE: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL,
			},
			"tacacs+",
		},
		{
			"String type",
			&ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_String{
				String: "custom-server-group",
			},
			"custom-server-group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAuthMethodString(tt.method)
			if result != tt.expected {
				t.Errorf("extractAuthMethodString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractAuthzMethodString(t *testing.T) {
	tests := []struct {
		name     string
		method   ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union
		expected string
	}{
		{
			"LOCAL enum type",
			&ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
				E_OpenconfigAaaTypes_AAA_METHOD_TYPE: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
			},
			"local",
		},
		{
			"String type",
			&ocbinds.OpenconfigSystem_System_Aaa_Authorization_Config_AuthorizationMethod_Union_String{
				String: "custom-authz-group",
			},
			"custom-authz-group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAuthzMethodString(tt.method)
			if result != tt.expected {
				t.Errorf("extractAuthzMethodString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractAcctMethodString(t *testing.T) {
	tests := []struct {
		name     string
		method   ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union
		expected string
	}{
		{
			"LOCAL enum type",
			&ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
				E_OpenconfigAaaTypes_AAA_METHOD_TYPE: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
			},
			"local",
		},
		{
			"String type",
			&ocbinds.OpenconfigSystem_System_Aaa_Accounting_Config_AccountingMethod_Union_String{
				String: "custom-acct-group",
			},
			"custom-acct-group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAcctMethodString(tt.method)
			if result != tt.expected {
				t.Errorf("extractAcctMethodString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHandleAaaDelete(t *testing.T) {
	tests := []struct {
		name          string
		targetUriPath string
		expectedKey   string
		expectedField string
	}{
		{"delete authentication-method", "/openconfig-system:system/aaa/authentication/config/authentication-method", AAA_AUTHENTICATION_KEY, AAA_LOGIN_FIELD},
		{"delete authorization-method", "/openconfig-system:system/aaa/authorization/config/authorization-method", AAA_AUTHORIZATION_KEY, AAA_LOGIN_FIELD},
		{"delete accounting-method", "/openconfig-system:system/aaa/accounting/config/accounting-method", AAA_ACCOUNTING_KEY, AAA_LOGIN_FIELD},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aaa_map := make(map[string]db.Value)
			res_map := make(map[string]map[string]db.Value)

			result, err := handleAaaDelete(tt.targetUriPath, aaa_map, res_map)
			if err != nil {
				t.Errorf("handleAaaDelete() error = %v", err)
				return
			}

			if _, ok := result[AAA_TABLE]; !ok {
				t.Errorf("handleAaaDelete() AAA_TABLE not found in result")
				return
			}

			if _, ok := result[AAA_TABLE][tt.expectedKey]; !ok {
				t.Errorf("handleAaaDelete() key %s not found in result", tt.expectedKey)
				return
			}

			if result[AAA_TABLE][tt.expectedKey].Field[tt.expectedField] != "" {
				t.Errorf("handleAaaDelete() field %s should be empty string", tt.expectedField)
			}
		})
	}
}

func TestHandleAaaDeleteUnknownPath(t *testing.T) {
	aaa_map := make(map[string]db.Value)
	res_map := make(map[string]map[string]db.Value)

	result, err := handleAaaDelete("/unknown/path", aaa_map, res_map)
	if err != nil {
		t.Errorf("handleAaaDelete() error = %v", err)
		return
	}

	if _, ok := result[AAA_TABLE]; ok {
		t.Errorf("handleAaaDelete() should not create AAA_TABLE for unknown path")
	}
}

func TestAaaAuthenticationKeyXfmr(t *testing.T) {
	inParams := XfmrParams{key: "test_key"}
	result, err := aaa_authentication_key_xfmr(inParams)
	if err != nil {
		t.Errorf("aaa_authentication_key_xfmr() error = %v", err)
		return
	}
	if result != AAA_AUTHENTICATION_KEY {
		t.Errorf("aaa_authentication_key_xfmr() = %v, want %v", result, AAA_AUTHENTICATION_KEY)
	}
}

func TestAaaAuthorizationKeyXfmr(t *testing.T) {
	inParams := XfmrParams{key: "test_key"}
	result, err := aaa_authorization_key_xfmr(inParams)
	if err != nil {
		t.Errorf("aaa_authorization_key_xfmr() error = %v", err)
		return
	}
	if result != AAA_AUTHORIZATION_KEY {
		t.Errorf("aaa_authorization_key_xfmr() = %v, want %v", result, AAA_AUTHORIZATION_KEY)
	}
}

func TestAaaAccountingKeyXfmr(t *testing.T) {
	inParams := XfmrParams{key: "test_key"}
	result, err := aaa_accounting_key_xfmr(inParams)
	if err != nil {
		t.Errorf("aaa_accounting_key_xfmr() error = %v", err)
		return
	}
	if result != AAA_ACCOUNTING_KEY {
		t.Errorf("aaa_accounting_key_xfmr() = %v, want %v", result, AAA_ACCOUNTING_KEY)
	}
}

func TestYangToDbAaaAuthMethodXfmr(t *testing.T) {
	tests := []struct {
		name     string
		param    interface{}
		expected map[string]string
	}{
		{"single method", []interface{}{"local"}, map[string]string{AAA_LOGIN_FIELD: "local"}},
		{"multiple methods", []interface{}{"tacacs+", "local"}, map[string]string{AAA_LOGIN_FIELD: "tacacs+,local"}},
		{"empty list", []interface{}{}, map[string]string{}},
		{"nil param", nil, map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{param: tt.param}
			result, err := YangToDb_aaa_auth_method_xfmr(inParams)
			if err != nil {
				t.Errorf("YangToDb_aaa_auth_method_xfmr() error = %v", err)
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("YangToDb_aaa_auth_method_xfmr() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDbToYangAaaAuthMethodXfmr(t *testing.T) {
	tests := []struct {
		name      string
		dbDataMap map[db.DBNum]map[string]map[string]db.Value
		curDb     db.DBNum
		expected  map[string]interface{}
	}{
		{
			"single method",
			map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {AAA_TABLE: {AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "local"}}}},
			},
			db.ConfigDB,
			map[string]interface{}{"authentication-method": []string{"local"}},
		},
		{
			"multiple methods",
			map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {AAA_TABLE: {AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "tacacs+,local"}}}},
			},
			db.ConfigDB,
			map[string]interface{}{"authentication-method": []string{"tacacs+", "local"}},
		},
		{
			"empty login field",
			map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {AAA_TABLE: {AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: ""}}}},
			},
			db.ConfigDB,
			map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{dbDataMap: &tt.dbDataMap, curDb: tt.curDb}
			result, err := DbToYang_aaa_auth_method_xfmr(inParams)
			if err != nil {
				t.Errorf("DbToYang_aaa_auth_method_xfmr() error = %v", err)
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DbToYang_aaa_auth_method_xfmr() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if AAA_TABLE != "AAA" {
		t.Errorf("AAA_TABLE = %v, want AAA", AAA_TABLE)
	}
	if AAA_AUTHENTICATION_KEY != "authentication" {
		t.Errorf("AAA_AUTHENTICATION_KEY = %v, want authentication", AAA_AUTHENTICATION_KEY)
	}
	if AAA_AUTHORIZATION_KEY != "authorization" {
		t.Errorf("AAA_AUTHORIZATION_KEY = %v, want authorization", AAA_AUTHORIZATION_KEY)
	}
	if AAA_ACCOUNTING_KEY != "accounting" {
		t.Errorf("AAA_ACCOUNTING_KEY = %v, want accounting", AAA_ACCOUNTING_KEY)
	}
	if AAA_LOGIN_FIELD != "login" {
		t.Errorf("AAA_LOGIN_FIELD = %v, want login", AAA_LOGIN_FIELD)
	}
}

func TestMethodTypeRoundTrip(t *testing.T) {
	methods := []ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE{
		ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
		ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL,
		ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL,
	}

	for _, method := range methods {
		str := methodTypeToString(method)
		result := stringToMethodType(str)
		if result != method {
			t.Errorf("Round trip failed for %v: got %v via string %s", method, result, str)
		}
	}
}
