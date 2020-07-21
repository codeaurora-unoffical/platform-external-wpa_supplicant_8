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
/*
 * vendor hidl interface for wpa_supplicant daemon
 *
 */

#include "hidl_manager.h"
#include "hidl_return_util.h"
#include "iface_config_utils.h"
#include "misc_utils.h"
#include "sta_iface.h"
#include "vendorsta_iface.h"

extern "C" {
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "gas_query.h"
#include "interworking.h"
#include "hs20_supplicant.h"
#include "wps_supplicant.h"
#include "common/dpp.h"
#include "dpp_supplicant.h"
#ifdef CONFIG_DPP
#include "common/dpp.h"
#endif
}

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor {
namespace V2_2 {
namespace Implementation {
using android::hardware::wifi::supplicant::V1_3::implementation::hidl_return_util::validateAndCall;

VendorStaIface::VendorStaIface(struct wpa_global *wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname), is_valid_(true)
{
}

void VendorStaIface::invalidate() { is_valid_ = false; }
bool VendorStaIface::isValid()
{
	return (is_valid_ && (retrieveIfacePtr() != nullptr));
}

Return<void> VendorStaIface::registerVendorCallback(
    const android::sp<ISupplicantVendorStaIfaceCallback> &callback,
    registerVendorCallback_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> VendorStaIface::filsHlpFlushRequest(filsHlpFlushRequest_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> VendorStaIface::filsHlpAddRequest(
    const hidl_array<uint8_t, 6> &dst_mac, const hidl_vec<uint8_t> &pkt,
    filsHlpAddRequest_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> VendorStaIface::getCapabilities(
    const hidl_string &capa_type, getCapabilities_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, "");
	return Void();
}

Return<void> VendorStaIface::getVendorNetwork(
    SupplicantNetworkId id, getVendorNetwork_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, nullptr);
	return Void();
}

Return<void> VendorStaIface::dppAddBootstrapQrcode(
    const hidl_string& uri, dppAddBootstrapQrcode_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppBootstrapGenerate(
    uint32_t type, const hidl_string& chan_list, const hidl_array<uint8_t, 6> &mac_addr,
    const hidl_string& info, const hidl_string& curve, const hidl_string& key,
    dppBootstrapGenerate_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppGetUri(uint32_t id, dppGetUri_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, "");
	return Void();
}

Return<void> VendorStaIface::dppBootstrapRemove(
    uint32_t id, dppBootstrapRemove_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppStartListen(
    const hidl_string& frequency, uint32_t dpp_role, bool qr_mutual,
    bool netrole_ap, dppStartListen_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppStopListen(dppStopListen_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"});
	return Void();
}

Return<void> VendorStaIface::dppConfiguratorAdd(
    const hidl_string& curve, const hidl_string& key, uint32_t expiry,
    dppConfiguratorAdd_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppConfiguratorRemove(
    uint32_t id, dppConfiguratorRemove_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppStartAuth(
    int32_t peer_bootstrap_id, int32_t own_bootstrap_id, int32_t dpp_role,
    const hidl_string& ssid, const hidl_string& password, bool isAp,
    bool isDpp, int32_t conf_id, int32_t expiry, dppStartAuth_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, -1);
	return Void();
}

Return<void> VendorStaIface::dppConfiguratorGetKey(uint32_t id, dppConfiguratorGetKey_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, "");
	return Void();
}

Return<void> VendorStaIface::getWifiGenerationStatus(getWifiGenerationStatus_cb _hidl_cb)
{
	_hidl_cb({SupplicantStatusCode::FAILURE_UNKNOWN, "NOT_SUPPORTED"}, {});
	return Void();
}

Return<void> VendorStaIface::doDriverCmd(
    const hidl_string& cmd,
    doDriverCmd_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &VendorStaIface::doDriverCmdInternal, _hidl_cb, cmd);
}

// private hidl implementation
std::pair<SupplicantStatus, std::string>
VendorStaIface::doDriverCmdInternal(const std::string& cmd)
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, "wpa_s fail"}, ""};
	}

	wpa_printf(MSG_INFO, "doDriverCmd[%s] - '%s'\n",
	    ifname_.c_str(), cmd.c_str());

	char *reply;
	const int reply_size = 4096;
	int ret;

	reply = (char*) os_zalloc(reply_size);
	if (reply == NULL) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, "malloc fail"}, ""};
	}

	/*
	 * ret > 0: GET success, buffer already filled.
	 * ret = 0: SET success, fill with buffer 'OK'.
	 * ret < 0: SET/GET fail, fill with buffer 'FAIL'.
	 */
	ret = wpa_drv_driver_cmd(wpa_s, (char *)cmd.c_str(), reply, reply_size);
	if (ret == 0) {
		ret = os_snprintf(reply, reply_size, "%s\n", "OK");
		if (os_snprintf_error(reply_size, ret))
			ret = -1;
	}
	if (ret < 0) {
		os_memcpy(reply, "FAIL\n", 5);
	}

	std::string str_reply(reply);
	os_free(reply);

	return {{SupplicantStatusCode::SUCCESS, ""}, str_reply};
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this iface.
 * If the underlying iface is removed, then all RPC method calls on this object
 * will return failure.
 */
wpa_supplicant *VendorStaIface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(wpa_global_, ifname_.c_str());
}
}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicant
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
