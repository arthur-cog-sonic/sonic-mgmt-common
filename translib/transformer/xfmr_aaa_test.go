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
		{
			name:     "LOCAL method",
			method:   ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
			expected: "local",
		},
		{
			name:     "TACACS_ALL method",
			method:   ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL,
			expected: "tacacs+",
		},
		{
			name:     "RADIUS_ALL method",
			method:   ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL,
			expected: "radius",
		},
		{
			name:     "UNSET method",
			method:   ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET,
			expected: "",
		},
		{
			name:     "Unknown method value",
			method:   ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE(999),
			expected: "",
		},
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
		{
			name:     "local lowercase",
			method:   "local",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
		},
		{
			name:     "LOCAL uppercase",
			method:   "LOCAL",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
		},
		{
			name:     "Local mixed case",
			method:   "Local",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL,
		},
		{
			name:     "tacacs+ lowercase",
			method:   "tacacs+",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL,
		},
		{
			name:     "TACACS+ uppercase",
			method:   "TACACS+",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL,
		},
		{
			name:     "radius lowercase",
			method:   "radius",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL,
		},
		{
			name:     "RADIUS uppercase",
			method:   "RADIUS",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL,
		},
		{
			name:     "unknown method",
			method:   "unknown",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET,
		},
		{
			name:     "empty string",
			method:   "",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET,
		},
		{
			name:     "ldap (unsupported)",
			method:   "ldap",
			expected: ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET,
		},
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

func TestFillBooleanField(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		field         string
		value         *bool
		expectedValue string
		expectField   bool
	}{
		{
			name:          "true value",
			key:           AAA_AUTHENTICATION_KEY,
			field:         AAA_FAILTHROUGH_FIELD,
			value:         boolPtr(true),
			expectedValue: "True",
			expectField:   true,
		},
		{
			name:          "false value",
			key:           AAA_AUTHENTICATION_KEY,
			field:         AAA_FALLBACK_FIELD,
			value:         boolPtr(false),
			expectedValue: "False",
			expectField:   true,
		},
		{
			name:          "nil value",
			key:           AAA_AUTHENTICATION_KEY,
			field:         AAA_DEBUG_FIELD,
			value:         nil,
			expectedValue: "",
			expectField:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aaa_map := make(map[string]db.Value)
			aaa_map[tt.key] = db.Value{Field: make(map[string]string)}

			fillBooleanField(aaa_map, tt.key, tt.field, tt.value)

			if tt.expectField {
				if val, ok := aaa_map[tt.key].Field[tt.field]; !ok || val != tt.expectedValue {
					t.Errorf("fillBooleanField() field %s = %v, want %v", tt.field, val, tt.expectedValue)
				}
			} else {
				if _, ok := aaa_map[tt.key].Field[tt.field]; ok {
					t.Errorf("fillBooleanField() field %s should not be set for nil value", tt.field)
				}
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
		{
			name:          "delete authentication-method",
			targetUriPath: "/openconfig-system:system/aaa/authentication/config/authentication-method",
			expectedKey:   AAA_AUTHENTICATION_KEY,
			expectedField: AAA_LOGIN_FIELD,
		},
		{
			name:          "delete failthrough",
			targetUriPath: "/openconfig-system:system/aaa/authentication/config/failthrough",
			expectedKey:   AAA_AUTHENTICATION_KEY,
			expectedField: AAA_FAILTHROUGH_FIELD,
		},
		{
			name:          "delete fallback",
			targetUriPath: "/openconfig-system:system/aaa/authentication/config/fallback",
			expectedKey:   AAA_AUTHENTICATION_KEY,
			expectedField: AAA_FALLBACK_FIELD,
		},
		{
			name:          "delete debug",
			targetUriPath: "/openconfig-system:system/aaa/authentication/config/debug",
			expectedKey:   AAA_AUTHENTICATION_KEY,
			expectedField: AAA_DEBUG_FIELD,
		},
		{
			name:          "delete trace",
			targetUriPath: "/openconfig-system:system/aaa/authentication/config/trace",
			expectedKey:   AAA_AUTHENTICATION_KEY,
			expectedField: AAA_TRACE_FIELD,
		},
		{
			name:          "delete authorization-method",
			targetUriPath: "/openconfig-system:system/aaa/authorization/config/authorization-method",
			expectedKey:   AAA_AUTHORIZATION_KEY,
			expectedField: AAA_LOGIN_FIELD,
		},
		{
			name:          "delete accounting-method",
			targetUriPath: "/openconfig-system:system/aaa/accounting/config/accounting-method",
			expectedKey:   AAA_ACCOUNTING_KEY,
			expectedField: AAA_LOGIN_FIELD,
		},
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

			if _, ok := result[AAA_TABLE][tt.expectedKey].Field[tt.expectedField]; !ok {
				t.Errorf("handleAaaDelete() field %s not found in result", tt.expectedField)
				return
			}

			if result[AAA_TABLE][tt.expectedKey].Field[tt.expectedField] != "" {
				t.Errorf("handleAaaDelete() field %s should be empty string, got %s",
					tt.expectedField, result[AAA_TABLE][tt.expectedKey].Field[tt.expectedField])
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
	inParams := XfmrParams{
		key: "test_key",
	}

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
	inParams := XfmrParams{
		key: "test_key",
	}

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
	inParams := XfmrParams{
		key: "test_key",
	}

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
		{
			name:     "single method",
			param:    []interface{}{"local"},
			expected: map[string]string{AAA_LOGIN_FIELD: "local"},
		},
		{
			name:     "multiple methods",
			param:    []interface{}{"tacacs+", "local"},
			expected: map[string]string{AAA_LOGIN_FIELD: "tacacs+,local"},
		},
		{
			name:     "empty list",
			param:    []interface{}{},
			expected: map[string]string{},
		},
		{
			name:     "nil param",
			param:    nil,
			expected: map[string]string{},
		},
		{
			name:     "non-slice param",
			param:    "local",
			expected: map[string]string{},
		},
		{
			name:     "mixed types in slice",
			param:    []interface{}{"local", 123, "radius"},
			expected: map[string]string{AAA_LOGIN_FIELD: "local,radius"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				param: tt.param,
			}

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

func TestYangToDbAaaAuthzMethodXfmr(t *testing.T) {
	tests := []struct {
		name     string
		param    interface{}
		expected map[string]string
	}{
		{
			name:     "single method",
			param:    []interface{}{"tacacs+"},
			expected: map[string]string{AAA_LOGIN_FIELD: "tacacs+"},
		},
		{
			name:     "multiple methods",
			param:    []interface{}{"radius", "local"},
			expected: map[string]string{AAA_LOGIN_FIELD: "radius,local"},
		},
		{
			name:     "empty list",
			param:    []interface{}{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				param: tt.param,
			}

			result, err := YangToDb_aaa_authz_method_xfmr(inParams)
			if err != nil {
				t.Errorf("YangToDb_aaa_authz_method_xfmr() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("YangToDb_aaa_authz_method_xfmr() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestYangToDbAaaAcctMethodXfmr(t *testing.T) {
	tests := []struct {
		name     string
		param    interface{}
		expected map[string]string
	}{
		{
			name:     "single method",
			param:    []interface{}{"local"},
			expected: map[string]string{AAA_LOGIN_FIELD: "local"},
		},
		{
			name:     "multiple methods",
			param:    []interface{}{"tacacs+", "radius", "local"},
			expected: map[string]string{AAA_LOGIN_FIELD: "tacacs+,radius,local"},
		},
		{
			name:     "empty list",
			param:    []interface{}{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				param: tt.param,
			}

			result, err := YangToDb_aaa_acct_method_xfmr(inParams)
			if err != nil {
				t.Errorf("YangToDb_aaa_acct_method_xfmr() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("YangToDb_aaa_acct_method_xfmr() = %v, want %v", result, tt.expected)
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
			name: "single method",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "local"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"authentication-method": []string{"local"}},
		},
		{
			name: "multiple methods",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "tacacs+,local"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"authentication-method": []string{"tacacs+", "local"}},
		},
		{
			name: "empty login field",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_AUTHENTICATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: ""}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{},
		},
		{
			name: "missing AAA table",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{},
		},
		{
			name: "missing authentication key",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				dbDataMap: &tt.dbDataMap,
				curDb:     tt.curDb,
			}

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

func TestDbToYangAaaAuthzMethodXfmr(t *testing.T) {
	tests := []struct {
		name      string
		dbDataMap map[db.DBNum]map[string]map[string]db.Value
		curDb     db.DBNum
		expected  map[string]interface{}
	}{
		{
			name: "single method",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_AUTHORIZATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "tacacs+"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"authorization-method": []string{"tacacs+"}},
		},
		{
			name: "multiple methods",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_AUTHORIZATION_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "radius,local"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"authorization-method": []string{"radius", "local"}},
		},
		{
			name: "missing authorization key",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				dbDataMap: &tt.dbDataMap,
				curDb:     tt.curDb,
			}

			result, err := DbToYang_aaa_authz_method_xfmr(inParams)
			if err != nil {
				t.Errorf("DbToYang_aaa_authz_method_xfmr() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DbToYang_aaa_authz_method_xfmr() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDbToYangAaaAcctMethodXfmr(t *testing.T) {
	tests := []struct {
		name      string
		dbDataMap map[db.DBNum]map[string]map[string]db.Value
		curDb     db.DBNum
		expected  map[string]interface{}
	}{
		{
			name: "single method",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_ACCOUNTING_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "local"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"accounting-method": []string{"local"}},
		},
		{
			name: "multiple methods",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {
						AAA_ACCOUNTING_KEY: db.Value{Field: map[string]string{AAA_LOGIN_FIELD: "tacacs+,radius,local"}},
					},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{"accounting-method": []string{"tacacs+", "radius", "local"}},
		},
		{
			name: "missing accounting key",
			dbDataMap: map[db.DBNum]map[string]map[string]db.Value{
				db.ConfigDB: {
					AAA_TABLE: {},
				},
			},
			curDb:    db.ConfigDB,
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inParams := XfmrParams{
				dbDataMap: &tt.dbDataMap,
				curDb:     tt.curDb,
			}

			result, err := DbToYang_aaa_acct_method_xfmr(inParams)
			if err != nil {
				t.Errorf("DbToYang_aaa_acct_method_xfmr() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DbToYang_aaa_acct_method_xfmr() = %v, want %v", result, tt.expected)
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
	if AAA_FAILTHROUGH_FIELD != "failthrough" {
		t.Errorf("AAA_FAILTHROUGH_FIELD = %v, want failthrough", AAA_FAILTHROUGH_FIELD)
	}
	if AAA_FALLBACK_FIELD != "fallback" {
		t.Errorf("AAA_FALLBACK_FIELD = %v, want fallback", AAA_FALLBACK_FIELD)
	}
	if AAA_DEBUG_FIELD != "debug" {
		t.Errorf("AAA_DEBUG_FIELD = %v, want debug", AAA_DEBUG_FIELD)
	}
	if AAA_TRACE_FIELD != "trace" {
		t.Errorf("AAA_TRACE_FIELD = %v, want trace", AAA_TRACE_FIELD)
	}
}

func TestMethodTypeRoundTrip(t *testing.T) {
	methods := []string{"local", "tacacs+", "radius"}

	for _, method := range methods {
		methodType := stringToMethodType(method)
		if methodType == ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_UNSET {
			t.Errorf("stringToMethodType(%s) returned UNSET", method)
			continue
		}

		result := methodTypeToString(methodType)
		if result != method {
			t.Errorf("Round trip failed: %s -> %v -> %s", method, methodType, result)
		}
	}
}

func boolPtr(b bool) *bool {
	return &b
}
