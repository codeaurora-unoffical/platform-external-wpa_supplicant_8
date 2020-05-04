/*
 * hidl interface for wpa_hostapd daemon
 * Copyright (c) 2004-2018, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2018, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_bridge.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include "hostapd.h"
#include "hidl_return_util.h"

extern "C"
{
#include "utils/eloop.h"
#include "drivers/linux_ioctl.h"

#define VENDOR_ENCRYPTION_TYPE_SAE 6
#define VENDOR_ENCRYPTION_TYPE_OWE 7
#define IHOSTAPD_HAL_BAND_DUAL 3 // FIXME: use HIDL definition in upcoming R.
}

// The HIDL implementation for hostapd creates a hostapd.conf dynamically for
// each interface. This file can then be used to hook onto the normal config
// file parsing logic in hostapd code.  Helps us to avoid duplication of code
// in the HIDL interface.
// TOOD(b/71872409): Add unit tests for this.
namespace {
constexpr char kConfFileNameFmt[] = "/data/vendor/wifi/hostapd/hostapd_%s.conf";

using android::base::RemoveFileIfExists;
using android::base::StringPrintf;
using android::base::WriteStringToFile;
using android::hardware::wifi::hostapd::V1_1::IHostapd;

#define MAX_PORTS 1024
bool GetInterfacesInBridge(std::string br_name,
                           std::vector<std::string>* interfaces) {
	android::base::unique_fd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
	if (sock.get() < 0) {
		wpa_printf(MSG_ERROR, "Failed to create sock (%s) in %s",
			strerror(errno), __FUNCTION__);
		return false;
	}

	struct ifreq request;
	int i, ifindices[MAX_PORTS];
	char if_name[IFNAMSIZ];
	unsigned long args[3];

	memset(ifindices, 0, MAX_PORTS);

	args[0] = BRCTL_GET_PORT_LIST;
	args[1] = (unsigned long) ifindices;
	args[2] = MAX_PORTS;

	strlcpy(request.ifr_name, br_name.c_str(), IFNAMSIZ);
	request.ifr_data = (char *)args;

	if (ioctl(sock.get(), SIOCDEVPRIVATE, &request) < 0) {
		wpa_printf(MSG_ERROR, "Failed to ioctl SIOCDEVPRIVATE in %s",
			__FUNCTION__);
		return false;
	}

	for (i = 0; i < MAX_PORTS; i ++) {
		memset(if_name, 0, IFNAMSIZ);
		if (ifindices[i] == 0 || !if_indextoname(ifindices[i], if_name)) {
			continue;
		}
		interfaces->push_back(if_name);
	}
	return true;
}

std::string WriteHostapdConfig(
    const std::string& interface_name, const std::string& config)
{
	const std::string file_path =
	    StringPrintf(kConfFileNameFmt, interface_name.c_str());
	if (WriteStringToFile(
		config, file_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
		getuid(), getgid())) {
		return file_path;
	}
	// Diagnose failure
	int error = errno;
	wpa_printf(
	    MSG_ERROR, "Cannot write hostapd config to %s, error: %s",
	    file_path.c_str(), strerror(error));
	struct stat st;
	int result = stat(file_path.c_str(), &st);
	if (result == 0) {
		wpa_printf(
		    MSG_ERROR, "hostapd config file uid: %d, gid: %d, mode: %d",
		    st.st_uid, st.st_gid, st.st_mode);
	} else {
		wpa_printf(
		    MSG_ERROR,
		    "Error calling stat() on hostapd config file: %s",
		    strerror(errno));
	}
	return "";
}

std::string CreateHostapdConfig(
    const IHostapd::IfaceParams& iface_params,
    const IHostapd::NetworkParams& nw_params,
    const std::string br_name)
{
	if (nw_params.ssid.size() >
	    static_cast<uint32_t>(
		IHostapd::ParamSizeLimits::SSID_MAX_LEN_IN_BYTES)) {
		wpa_printf(
		    MSG_ERROR, "Invalid SSID size: %zu", nw_params.ssid.size());
		return "";
	}
	if ((nw_params.encryptionType != IHostapd::EncryptionType::NONE &&
#ifdef CONFIG_OWE
	     static_cast<uint32_t>(nw_params.encryptionType) != VENDOR_ENCRYPTION_TYPE_OWE) &&
#endif
	    (nw_params.pskPassphrase.size() <
		 static_cast<uint32_t>(
		     IHostapd::ParamSizeLimits::
			 WPA2_PSK_PASSPHRASE_MIN_LEN_IN_BYTES) ||
	     nw_params.pskPassphrase.size() >
		 static_cast<uint32_t>(
		     IHostapd::ParamSizeLimits::
			 WPA2_PSK_PASSPHRASE_MAX_LEN_IN_BYTES))) {
		wpa_printf(
		    MSG_ERROR, "Invalid psk passphrase size: %zu",
		    nw_params.pskPassphrase.size());
		return "";
	}

	// SSID string
	std::stringstream ss;
	ss << std::hex;
	ss << std::setfill('0');
	for (uint8_t b : nw_params.ssid) {
		ss << std::setw(2) << static_cast<unsigned int>(b);
	}
	const std::string ssid_as_string = ss.str();

	// Encryption config string
	std::string encryption_config_as_string;
	switch (static_cast<uint32_t>(nw_params.encryptionType)) {
	case static_cast<uint32_t>(IHostapd::EncryptionType::NONE):
		// no security params
		break;
	case static_cast<uint32_t>(IHostapd::EncryptionType::WPA):
		encryption_config_as_string = StringPrintf(
		    "wpa=3\n"
		    "wpa_pairwise=TKIP CCMP\n"
		    "wpa_passphrase=%s",
		    nw_params.pskPassphrase.c_str());
		break;
	case static_cast<uint32_t>(IHostapd::EncryptionType::WPA2):
		encryption_config_as_string = StringPrintf(
		    "wpa=2\n"
		    "rsn_pairwise=CCMP\n"
		    "wpa_passphrase=%s",
		    nw_params.pskPassphrase.c_str());
		break;
#ifdef CONFIG_OWE
	case VENDOR_ENCRYPTION_TYPE_OWE:
		encryption_config_as_string =
		    "wpa=2\n"
		    "rsn_pairwise=CCMP\n"
		    "wpa_key_mgmt=OWE\n"
		    "ieee80211w=2";
		break;
#endif
#ifdef CONFIG_SAE
	case VENDOR_ENCRYPTION_TYPE_SAE:
		encryption_config_as_string = StringPrintf(
		    "wpa=2\n"
		    "wpa_pairwise=CCMP\n"
		    "wpa_key_mgmt=SAE WPA-PSK\n"
		    "ieee80211w=1\n"
		    "sae_require_mfp=1\n"
		    "wpa_passphrase=%s",
		    nw_params.pskPassphrase.c_str());
		break;
#endif
	default:
		wpa_printf(MSG_ERROR, "Unknown encryption type");
		return "";
	}

	std::string channel_config_as_string;
	if (iface_params.V1_0.channelParams.enableAcs) {
		std::string chanlist_as_string;
		for (const auto &range :
		     iface_params.channelParams.acsChannelRanges) {
			if (range.start != range.end) {
				chanlist_as_string +=
					StringPrintf("%d-%d ", range.start, range.end);
			} else {
				chanlist_as_string += StringPrintf("%d ", range.start);
			}
		}
		channel_config_as_string = StringPrintf(
		    "channel=0\n"
		    "acs_exclude_dfs=%d\n"
		    "chanlist=%s",
		    iface_params.V1_0.channelParams.acsShouldExcludeDfs,
		    chanlist_as_string.c_str());
	} else {
		channel_config_as_string = StringPrintf(
		    "channel=%d", iface_params.V1_0.channelParams.channel);
	}

	// Hw Mode String
	std::string hw_mode_as_string;
	std::string ht_cap_vht_oper_chwidth_as_string;
	switch (iface_params.V1_0.channelParams.band) {
	case IHostapd::Band::BAND_2_4_GHZ:
		hw_mode_as_string = "hw_mode=g";
		break;
	case IHostapd::Band::BAND_5_GHZ:
		hw_mode_as_string = "hw_mode=a";
		if (iface_params.V1_0.channelParams.enableAcs) {
			ht_cap_vht_oper_chwidth_as_string =
			    "ht_capab=[HT40+]\n"
			    "vht_oper_chwidth=1";
		}
		break;
	case IHostapd::Band::BAND_ANY:
		hw_mode_as_string = "hw_mode=any";
		if (iface_params.V1_0.channelParams.enableAcs) {
			ht_cap_vht_oper_chwidth_as_string =
			    "ht_capab=[HT40+]\n"
			    "vht_oper_chwidth=1";
		}
		break;
	default:
		wpa_printf(MSG_ERROR, "Invalid band");
		return "";
	}

	std::string bridge_as_string;
	if (!br_name.empty()) {
		bridge_as_string = StringPrintf("bridge=%s", br_name.c_str());
	}

	return StringPrintf(
	    "interface=%s\n"
	    "driver=nl80211\n"
	    "ctrl_interface=/data/vendor/wifi/hostapd/ctrl\n"
	    // ssid2 signals to hostapd that the value is not a literal value
	    // for use as a SSID.  In this case, we're giving it a hex
	    // std::string and hostapd needs to expect that.
	    "ssid2=%s\n"
	    "%s\n"
	    "ieee80211n=%d\n"
	    "ieee80211ac=%d\n"
	    "%s\n"
	    "%s\n"
	    "ignore_broadcast_ssid=%d\n"
	    "wowlan_triggers=any\n"
	    "%s\n"
	    "%s\n",
	    iface_params.V1_0.ifaceName.c_str(), ssid_as_string.c_str(),
	    channel_config_as_string.c_str(),
	    iface_params.V1_0.hwModeParams.enable80211N ? 1 : 0,
	    iface_params.V1_0.hwModeParams.enable80211AC ? 1 : 0,
	    hw_mode_as_string.c_str(), ht_cap_vht_oper_chwidth_as_string.c_str(),
	    nw_params.isHidden ? 1 : 0, encryption_config_as_string.c_str(),
	    bridge_as_string.c_str());
}

// hostapd core functions accept "C" style function pointers, so use global
// functions to pass to the hostapd core function and store the corresponding
// std::function methods to be invoked.
//
// NOTE: Using the pattern from the vendor HAL (wifi_legacy_hal.cpp).
//
// Callback to be invoked once setup is complete
std::function<void(struct hostapd_data*)> on_setup_complete_internal_callback;
void onAsyncSetupCompleteCb(void* ctx)
{
	struct hostapd_data* iface_hapd = (struct hostapd_data*)ctx;
	if (on_setup_complete_internal_callback) {
		on_setup_complete_internal_callback(iface_hapd);
		// Invalidate this callback since we don't want this firing
		// again. (allows for AP+AP)
//		on_setup_complete_internal_callback = nullptr;
	}
}
}  // namespace

namespace android {
namespace hardware {
namespace wifi {
namespace hostapd {
namespace V1_1 {
namespace implementation {
using hidl_return_util::call;
using namespace android::hardware::wifi::hostapd::V1_0;

Hostapd::Hostapd(struct hapd_interfaces* interfaces) : interfaces_(interfaces)
{}

Return<void> Hostapd::addAccessPoint(
    const V1_0::IHostapd::IfaceParams& iface_params,
    const NetworkParams& nw_params, addAccessPoint_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::addAccessPointInternal, _hidl_cb, iface_params,
	    nw_params);
}

Return<void> Hostapd::addAccessPoint_1_1(
    const IfaceParams& iface_params, const NetworkParams& nw_params,
    addAccessPoint_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::addAccessPointInternal_1_1, _hidl_cb, iface_params,
	    nw_params);
}

Return<void> Hostapd::removeAccessPoint(
    const hidl_string& iface_name, removeAccessPoint_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::removeAccessPointInternal, _hidl_cb, iface_name);
}

Return<void> Hostapd::terminate()
{
	wpa_printf(MSG_INFO, "Terminating...");
	eloop_terminate();
	return Void();
}

Return<void> Hostapd::registerCallback(
    const sp<IHostapdCallback>& callback, registerCallback_cb _hidl_cb)
{
	return call(
	    this, &Hostapd::registerCallbackInternal, _hidl_cb, callback);
}

HostapdStatus Hostapd::addAccessPointInternal(
    const V1_0::IHostapd::IfaceParams& iface_params,
    const NetworkParams& nw_params)
{
	return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
}

HostapdStatus Hostapd::addAccessPointInternal_1_1(
    const IfaceParams& iface_params, const NetworkParams& nw_params)
{
	if (static_cast<uint32_t>(iface_params.V1_0.channelParams.band)
		    != IHOSTAPD_HAL_BAND_DUAL) {
		wpa_printf(MSG_INFO, "AddSingleAccessPoint, iface=%s",
			iface_params.V1_0.ifaceName.c_str());
		return addSingleAccessPoint(iface_params, nw_params, "");
	} else {
		wpa_printf(MSG_INFO, "AddDualAccessPoint, iface=%s",
			iface_params.V1_0.ifaceName.c_str());
		return addDualAccessPoint(iface_params, nw_params);
	}
}

HostapdStatus Hostapd::addSingleAccessPoint(
    const IfaceParams& iface_params, const NetworkParams& nw_params,
    const std::string br_name)
{
	if (hostapd_get_iface(interfaces_, iface_params.V1_0.ifaceName.c_str())) {
		wpa_printf(
		    MSG_ERROR, "Interface %s already present",
		    iface_params.V1_0.ifaceName.c_str());
		return {HostapdStatusCode::FAILURE_IFACE_EXISTS, ""};
	}
	const auto conf_params = CreateHostapdConfig(iface_params, nw_params, br_name);
	if (conf_params.empty()) {
		wpa_printf(MSG_ERROR, "Failed to create config params");
		return {HostapdStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	const auto conf_file_path =
	    WriteHostapdConfig(iface_params.V1_0.ifaceName, conf_params);
	if (conf_file_path.empty()) {
		wpa_printf(MSG_ERROR, "Failed to write config file");
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}
	std::string add_iface_param_str = StringPrintf(
	    "%s config=%s", iface_params.V1_0.ifaceName.c_str(),
	    conf_file_path.c_str());
	std::vector<char> add_iface_param_vec(
	    add_iface_param_str.begin(), add_iface_param_str.end() + 1);
	if (hostapd_add_iface(interfaces_, add_iface_param_vec.data()) < 0) {
		wpa_printf(
		    MSG_ERROR, "Adding interface %s failed",
		    add_iface_param_str.c_str());
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}
	struct hostapd_data* iface_hapd =
	    hostapd_get_iface(interfaces_, iface_params.V1_0.ifaceName.c_str());
	WPA_ASSERT(iface_hapd != nullptr && iface_hapd->iface != nullptr);
	// Register the setup complete callbacks
	on_setup_complete_internal_callback =
	    [this](struct hostapd_data* iface_hapd) {
		    wpa_printf(
			MSG_INFO, "AP interface setup completed - state %s",
			hostapd_state_text(iface_hapd->iface->state));
		    if (iface_hapd->iface->state == HAPD_IFACE_DISABLED) {
			    // Invoke the failure callback on all registered
			    // clients.
			    for (const auto& callback : callbacks_) {
				    callback->onFailure(
					iface_hapd->conf->iface);
			    }
		    }
	    };

	iface_hapd->setup_complete_cb = onAsyncSetupCompleteCb;
	iface_hapd->setup_complete_cb_ctx = iface_hapd;
	if (hostapd_enable_iface(iface_hapd->iface) < 0) {
		wpa_printf(
		    MSG_ERROR, "Enabling interface %s failed",
		    iface_params.V1_0.ifaceName.c_str());
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {HostapdStatusCode::SUCCESS, ""};
}

HostapdStatus Hostapd::addDualAccessPoint(
    const IfaceParams& iface_params, const NetworkParams& nw_params)
{
	HostapdStatus status;
	std::string br_name;
	IfaceParams iface_params_new;

	// Prepare values
	br_name = StringPrintf("%s", iface_params.V1_0.ifaceName.c_str());
	iface_params_new = iface_params;

	// Get mananged interfaces from bridge
	std::vector<std::string> managed_interfaces;

	if (!GetInterfacesInBridge(br_name, &managed_interfaces)) {
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}

	if (managed_interfaces.size() != 2) {
		wpa_printf(MSG_ERROR, "Error %u interfaces at bridge %s",
			(uint32_t)managed_interfaces.size(), br_name.c_str());
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}

	std::string ifaceName2G = managed_interfaces[0];
	std::string ifaceName5G = managed_interfaces[1];

	// Add 2G Access Point.
	iface_params_new.V1_0.ifaceName = ifaceName2G;
	iface_params_new.V1_0.channelParams.band = V1_0::IHostapd::Band::BAND_2_4_GHZ;
	status = addSingleAccessPoint(iface_params_new, nw_params, br_name);
	if (status.code != HostapdStatusCode::SUCCESS) {
		wpa_printf(MSG_ERROR, "Failed to addAccessPoint %s", ifaceName2G.c_str());
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}

	// Add 5G Access Point.
	iface_params_new.V1_0.ifaceName = ifaceName5G;
	iface_params_new.V1_0.channelParams.band = V1_0::IHostapd::Band::BAND_5_GHZ;
	status = addSingleAccessPoint(iface_params_new, nw_params, br_name);
	if (status.code != HostapdStatusCode::SUCCESS) {
		wpa_printf(MSG_ERROR, "Failed to addAccessPoint %s", ifaceName5G.c_str());
		return {HostapdStatusCode::FAILURE_UNKNOWN, ""};
	}

	// Save bridge interface info
	br_interfaces_[br_name] = managed_interfaces;

	return {HostapdStatusCode::SUCCESS, ""};
}

HostapdStatus Hostapd::removeAccessPointInternal(const std::string& iface_name)
{
	// interfaces to be removed
	std::vector<std::string> interfaces;

	auto it = br_interfaces_.find(iface_name);
	if (it != br_interfaces_.end()) {
		// In case bridge, remove managed interfaces
		interfaces = it->second;
		br_interfaces_.erase(iface_name);
	} else {
		// else remove current interface
		interfaces.push_back(iface_name);
	}

	for (auto& iface : interfaces) {
		std::vector<char> remove_iface_param_vec(
		    iface.begin(), iface.end() + 1);

		if (hostapd_remove_iface(interfaces_, remove_iface_param_vec.data()) <
		    0) {
			wpa_printf(
			    MSG_INFO, "Remove interface %s failed",
			    iface.c_str());
			// continue
		}
	}
	return {HostapdStatusCode::SUCCESS, ""};
}

HostapdStatus Hostapd::registerCallbackInternal(
    const sp<IHostapdCallback>& callback)
{
	callbacks_.push_back(callback);
	return {HostapdStatusCode::SUCCESS, ""};
}

}  // namespace implementation
}  // namespace V1_1
}  // namespace hostapd
}  // namespace wifi
}  // namespace hardware
}  // namespace android
