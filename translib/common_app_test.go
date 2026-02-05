////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2024 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package translib

import (
	"reflect"
	"testing"
)

func TestOpenConfigAaaPathRegistration(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"AAA root path", "/openconfig-system:system/aaa"},
		{"AAA authentication path", "/openconfig-system:system/aaa/authentication"},
		{"AAA authentication config path", "/openconfig-system:system/aaa/authentication/config"},
		{"AAA authentication config method path", "/openconfig-system:system/aaa/authentication/config/authentication-method"},
		{"AAA authorization path", "/openconfig-system:system/aaa/authorization"},
		{"AAA authorization config path", "/openconfig-system:system/aaa/authorization/config"},
		{"AAA authorization config method path", "/openconfig-system:system/aaa/authorization/config/authorization-method"},
		{"AAA accounting path", "/openconfig-system:system/aaa/accounting"},
		{"AAA accounting config path", "/openconfig-system:system/aaa/accounting/config"},
		{"AAA accounting config method path", "/openconfig-system:system/aaa/accounting/config/accounting-method"},
		{"AAA server-groups path", "/openconfig-system:system/aaa/server-groups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appInfo, err := getAppModuleInfo(tt.path)
			if err != nil {
				t.Errorf("getAppModuleInfo(%s) returned error: %v", tt.path, err)
				return
			}
			if appInfo == nil {
				t.Errorf("getAppModuleInfo(%s) returned nil appInfo", tt.path)
				return
			}
			if appInfo.appType != reflect.TypeOf(CommonApp{}) {
				t.Errorf("getAppModuleInfo(%s) returned wrong app type: got %v, want %v",
					tt.path, appInfo.appType, reflect.TypeOf(CommonApp{}))
			}
		})
	}
}

func TestAaaPathExplicitRegistration(t *testing.T) {
	aaaPath := "/openconfig-system:system/aaa"
	if _, ok := appMap[aaaPath]; !ok {
		t.Errorf("AAA path %s is not explicitly registered in appMap", aaaPath)
	}
}

func TestAaaPathPrecedenceOverWildcard(t *testing.T) {
	aaaPath := "/openconfig-system:system/aaa/authentication"
	appInfo, err := getAppModuleInfo(aaaPath)
	if err != nil {
		t.Errorf("getAppModuleInfo(%s) returned error: %v", aaaPath, err)
		return
	}

	wildcardAppInfo := appMap["*"]
	if wildcardAppInfo == nil {
		t.Skip("Wildcard app not registered, skipping precedence test")
		return
	}

	if appInfo.appType != reflect.TypeOf(CommonApp{}) {
		t.Errorf("AAA path should be handled by CommonApp, got %v", appInfo.appType)
	}
}

func TestSonicPathRegistration(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"Sonic AAA path", "/sonic-system-aaa:sonic-system-aaa/AAA"},
		{"Sonic generic path", "/sonic-port:sonic-port/PORT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appInfo, err := getAppModuleInfo(tt.path)
			if err != nil {
				t.Errorf("getAppModuleInfo(%s) returned error: %v", tt.path, err)
				return
			}
			if appInfo == nil {
				t.Errorf("getAppModuleInfo(%s) returned nil appInfo", tt.path)
				return
			}
			if appInfo.appType != reflect.TypeOf(CommonApp{}) {
				t.Errorf("getAppModuleInfo(%s) returned wrong app type: got %v, want %v",
					tt.path, appInfo.appType, reflect.TypeOf(CommonApp{}))
			}
		})
	}
}
