/* Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* vendor hidl interface for hostapd daemon */

#include <string>

#include "hostapd_vendor.h"
#include "hidl_return_util.h"

extern "C"
{
#include "utils/eloop.h"
#include "ctrl_iface.h"
}


namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace hostapd {
namespace V1_2 {
namespace implementation {

using namespace android::hardware;
using namespace android::hardware::wifi::hostapd::V1_0;
using namespace android::hardware::wifi::hostapd::V1_2::implementation::hidl_return_util;

HostapdVendor::HostapdVendor(struct hapd_interfaces* interfaces)
    : interfaces_(interfaces) {}

// public hidl calls
Return<void> HostapdVendor::addVendorAccessPoint(
    const V1_0::IHostapdVendor::VendorIfaceParams& iface_params,
    const NetworkParams& nw_params,
    addVendorAccessPoint_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::addVendorAccessPoint_1_1(
    const V1_1::IHostapdVendor::VendorIfaceParams& iface_params,
    const NetworkParams& nw_params,
    addVendorAccessPoint_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::addVendorAccessPoint_1_2(
    const VendorIfaceParams& iface_params,
    const VendorNetworkParams& nw_params,
    addVendorAccessPoint_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::removeVendorAccessPoint(
    const hidl_string& iface_name, removeVendorAccessPoint_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::setHostapdParams(
    const hidl_string& cmd, setHostapdParams_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::setDebugParams(
    IHostapdVendor::DebugLevel level, bool show_timestamp, bool show_keys,
    setDebugParams_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<IHostapdVendor::DebugLevel> HostapdVendor::getDebugLevel()
{
	return (V1_1::IHostapdVendor::DebugLevel)wpa_debug_level;
}

Return<void> HostapdVendor::registerVendorCallback(
    const hidl_string& iface_name,
    const android::sp<V1_0::IHostapdVendorIfaceCallback> &callback,
    registerVendorCallback_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::registerVendorCallback_1_1(
    const hidl_string& iface_name,
    const android::sp<V1_1::IHostapdVendorIfaceCallback> &callback,
    registerVendorCallback_cb _hidl_cb)
{
	_hidl_cb({HostapdStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> HostapdVendor::listInterfaces(
    listInterfaces_cb _hidl_cb)
{
	return call(
	    this, &HostapdVendor::listInterfacesInternal, _hidl_cb);
}

Return<void> HostapdVendor::hostapdCmd(
    const hidl_string& iface_name,
    const hidl_string& cmd,
    hostapdCmd_cb _hidl_cb)
{
	return call(
	    this, &HostapdVendor::hostapdCmdInternal, _hidl_cb, iface_name, cmd);
}


// private hidl implementation
std::pair<HostapdStatus, std::vector<hidl_string>>
HostapdVendor::listInterfacesInternal()
{
	if (!interfaces_ || !interfaces_->iface) {
		return {{HostapdStatusCode::FAILURE_UNKNOWN, "_interfaces error"}, {}};
	}

	std::vector<hidl_string> names;
	for (size_t i = 0; i < interfaces_->count; i++) {
		struct hostapd_iface *iface = interfaces_->iface[i];
		for (size_t j = 0; j < iface->num_bss; j++) {
			struct hostapd_data *hapd = iface->bss[j];
			names.emplace_back(hapd->conf->iface);
		}
	}
	wpa_printf(MSG_INFO, "listInterfaces() - size=%d", (int)names.size());

	return {{HostapdStatusCode::SUCCESS, ""}, names};
}

std::pair<HostapdStatus, std::string>
HostapdVendor::hostapdCmdInternal(const std::string& iface_name, const std::string& cmd)
{
	if (!interfaces_ || !interfaces_->iface) {
		return {{HostapdStatusCode::FAILURE_UNKNOWN, "_interfaces error"}, ""};
	}

	wpa_printf(MSG_INFO, "hostapdCmd[%s] - '%s'\n",
	    iface_name.c_str() , cmd.c_str());

	struct hostapd_data* iface_hapd =
		    hostapd_get_iface(interfaces_, iface_name.c_str());
	if (!iface_hapd || !iface_hapd->iface) {
		return {{HostapdStatusCode::FAILURE_UNKNOWN, "iface not exist"}, ""};
	}

	if (iface_hapd->iface->state != HAPD_IFACE_ENABLED
	    && iface_hapd->iface->state != HAPD_IFACE_DFS) {
		return {{HostapdStatusCode::FAILURE_UNKNOWN, "iface not ready"}, ""};
	}

	char *reply;
	const int reply_size = 4096;
	int reply_len;

	reply = (char*) os_malloc(reply_size);
	if (reply == NULL) {
		return {{HostapdStatusCode::FAILURE_UNKNOWN, "memory alloc error"}, ""};
	}
	reply_len = hostapd_ctrl_iface_receive_process(iface_hapd, (char *)cmd.c_str(),
						       reply, reply_size,
						       NULL, 0);
	if (reply_len > reply_size) reply_len = reply_size;
	reply[reply_len] = '\0'; // make sure '\0' terminated.

	std::string str_reply(reply);
	os_free(reply);

	return {{HostapdStatusCode::SUCCESS, ""}, str_reply};
}


}  // namespace implementation
}  // namespace V1_2
}  // namespace hostapd
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
