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

// TestOpenConfigAaaPathRegistration validates that OpenConfig AAA paths
// are handled by CommonApp through the getAppModuleInfo function.
func TestOpenConfigAaaPathRegistration(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"AAA root path", "/openconfig-system:system/aaa"},
		{"AAA authentication path", "/openconfig-system:system/aaa/authentication"},
		{"AAA authentication config path", "/openconfig-system:system/aaa/authentication/config"},
		{"AAA authorization path", "/openconfig-system:system/aaa/authorization"},
		{"AAA accounting path", "/openconfig-system:system/aaa/accounting"},
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
			// Verify that the app type is CommonApp
			expectedType := reflect.TypeOf(CommonApp{})
			if appInfo.appType != expectedType {
				t.Errorf("getAppModuleInfo(%s) returned wrong app type: got %v, want %v",
					tt.path, appInfo.appType, expectedType)
			}
		})
	}
}

// TestSonicPathRegistration validates that SONiC paths are handled by CommonApp.
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
			// Verify that the app type is CommonApp
			expectedType := reflect.TypeOf(CommonApp{})
			if appInfo.appType != expectedType {
				t.Errorf("getAppModuleInfo(%s) returned wrong app type: got %v, want %v",
					tt.path, appInfo.appType, expectedType)
			}
		})
	}
}
