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

//go:build testapp
// +build testapp

package transformer_test

import (
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"testing"
	"time"
)

func Test_aaa_authentication_failthrough(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication failthrough ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"openconfig-aaa-ext:failthrough":true}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"failthrough": "True"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA failthrough enable", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA failthrough enable", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication failthrough ++++++++++++")

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication failthrough disable ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"openconfig-aaa-ext:failthrough":false}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"failthrough": "False"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA failthrough disable", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA failthrough disable", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication failthrough disable ++++++++++++")
}

func Test_aaa_authentication_login(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication login ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"authentication-method":["local","radius"]}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"login": "local,radius"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA login local radius", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA login local radius", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication login ++++++++++++")

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication login single method ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"authentication-method":["radius"]}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"login": "radius"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA login radius", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA login radius", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication login single method ++++++++++++")
}

func Test_aaa_authorization(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA authorization ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authorization":{"config":{"authorization-method":["tacacs+","local"]}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authorization": map[string]interface{}{"login": "tacacs+,local"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authorization": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA authorization tacacs+ local", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA authorization tacacs+ local", verifyDbResult(rclient, "AAA|authorization", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authorization ++++++++++++")
}

func Test_aaa_accounting(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA accounting ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"accounting":{"config":{"accounting-method":["tacacs+"]}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"accounting": map[string]interface{}{"login": "tacacs+"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"accounting": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA accounting tacacs+", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA accounting tacacs+", verifyDbResult(rclient, "AAA|accounting", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA accounting ++++++++++++")
}

func Test_aaa_authentication_fallback(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication fallback ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"openconfig-aaa-ext:fallback":true}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"fallback": "True"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA fallback enable", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA fallback enable", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication fallback ++++++++++++")
}

func Test_aaa_authentication_debug(t *testing.T) {
	var pre_req_map, expected_map, cleanuptbl map[string]interface{}
	var url, url_body_json string

	t.Log("\n\n+++++++++++++ Performing Set on AAA authentication debug ++++++++++++")
	url = "/openconfig-system:system/aaa"
	url_body_json = `{"openconfig-system:aaa":{"authentication":{"config":{"openconfig-aaa-ext:debug":true}}}}`
	expected_map = map[string]interface{}{"AAA": map[string]interface{}{"authentication": map[string]interface{}{"debug": "True"}}}
	cleanuptbl = map[string]interface{}{"AAA": map[string]interface{}{"authentication": ""}}
	loadDB(db.ConfigDB, pre_req_map)
	time.Sleep(1 * time.Second)
	t.Run("Test set AAA debug enable", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify AAA debug enable", verifyDbResult(rclient, "AAA|authentication", expected_map, false))
	time.Sleep(1 * time.Second)
	unloadDB(db.ConfigDB, cleanuptbl)
	time.Sleep(1 * time.Second)
	t.Log("\n\n+++++++++++++ Done Performing Set on AAA authentication debug ++++++++++++")
}
