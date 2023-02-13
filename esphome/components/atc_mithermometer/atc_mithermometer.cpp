#include "atc_mithermometer.h"
#include "esphome/core/log.h"

#ifdef USE_ESP32

#include <vector>
#include "mbedtls/ccm.h"

namespace esphome {
namespace atc_mithermometer {

static const char *const TAG = "atc_mithermometer";

void ATCMiThermometer::dump_config() {
  ESP_LOGCONFIG(TAG, "ATC MiThermometer");
  ESP_LOGCONFIG(TAG, "  Bindkey: %s", format_hex_pretty(this->bindkey_, 16).c_str());
  LOG_SENSOR("  ", "Temperature", this->temperature_);
  LOG_SENSOR("  ", "Humidity", this->humidity_);
  LOG_SENSOR("  ", "Battery Level", this->battery_level_);
  LOG_SENSOR("  ", "Battery Voltage", this->battery_voltage_);
}

bool ATCMiThermometer::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  if (device.address_uint64() != this->address_) {
    ESP_LOGVV(TAG, "parse_device(): unknown MAC address.");
    return false;
  }
  ESP_LOGVV(TAG, "parse_device(): MAC address %s found.", device.address_str().c_str());

  bool success = false;
  for (auto &service_data : device.get_service_datas()) {
    auto res = parse_header_(service_data);
    if (!res.has_value()) {
      continue;
    }
    if (res->has_encryption &&
        (!(decrypt_payload(const_cast<std::vector<uint8_t> &>(service_data.data), this->bindkey_,
                                              this->address_)))) {
      continue;
    }
    if (!(parse_message_(service_data.data, *res))) {
      continue;
    }
    if (!(report_results_(res, device.address_str()))) {
      continue;
    }
    if (res->temperature.has_value() && this->temperature_ != nullptr)
      this->temperature_->publish_state(*res->temperature);
    if (res->humidity.has_value() && this->humidity_ != nullptr)
      this->humidity_->publish_state(*res->humidity);
    if (res->battery_level.has_value() && this->battery_level_ != nullptr)
      this->battery_level_->publish_state(*res->battery_level);
    if (res->battery_voltage.has_value() && this->battery_voltage_ != nullptr)
      this->battery_voltage_->publish_state(*res->battery_voltage);
    success = true;
  }
  if (this->signal_strength_ != nullptr)
    this->signal_strength_->publish_state(device.get_rssi());

  return success;
}

optional<ParseResult> ATCMiThermometer::parse_header_(const esp32_ble_tracker::ServiceData &service_data) {
  ParseResult result;
  if (!service_data.uuid.contains(0x1A, 0x18)) {
    ESP_LOGVV(TAG, "parse_header(): no service data UUID magic bytes.");
    return {};
  }

  auto raw = service_data.data;
  result.has_encryption = raw[0] & 0x08;

  static uint8_t last_frame_count = 0;
  if (last_frame_count == raw[12]) {
    ESP_LOGVV(TAG, "parse_header(): duplicate data packet received (%hhu).", last_frame_count);
    return {};
  }
  last_frame_count = raw[12];

  return result;
}

bool ATCMiThermometer::parse_message_(const std::vector<uint8_t> &message, ParseResult &result) {
  // Byte 0-5 mac in correct order
  // Byte 6-7 Temperature in uint16
  // Byte 8 Humidity in percent
  // Byte 9 Battery in percent
  // Byte 10-11 Battery in mV uint16_t
  // Byte 12 frame packet counter

  const uint8_t *data = message.data();
  const int data_length = 13;

  if (message.size() != data_length) {
    ESP_LOGVV(TAG, "parse_message(): payload has wrong size (%d)!", message.size());
    return false;
  }

  // temperature, 2 bytes, 16-bit signed integer (LE), 0.1 °C
  const int16_t temperature = uint16_t(data[7]) | (uint16_t(data[6]) << 8);
  result.temperature = temperature / 10.0f;

  // humidity, 1 byte, 8-bit unsigned integer, 1.0 %
  result.humidity = data[8];

  // battery, 1 byte, 8-bit unsigned integer,  1.0 %
  result.battery_level = data[9];

  // battery, 2 bytes, 16-bit unsigned integer,  0.001 V
  const int16_t battery_voltage = uint16_t(data[11]) | (uint16_t(data[10]) << 8);
  result.battery_voltage = battery_voltage / 1.0e3f;

  return true;
}

bool ATCMiThermometer::report_results_(const optional<ParseResult> &result, const std::string &address) {
  if (!result.has_value()) {
    ESP_LOGVV(TAG, "report_results(): no results available.");
    return false;
  }

  ESP_LOGD(TAG, "Got ATC MiThermometer (%s):", address.c_str());

  if (result->temperature.has_value()) {
    ESP_LOGD(TAG, "  Temperature: %.1f °C", *result->temperature);
  }
  if (result->humidity.has_value()) {
    ESP_LOGD(TAG, "  Humidity: %.0f %%", *result->humidity);
  }
  if (result->battery_level.has_value()) {
    ESP_LOGD(TAG, "  Battery Level: %.0f %%", *result->battery_level);
  }
  if (result->battery_voltage.has_value()) {
    ESP_LOGD(TAG, "  Battery Voltage: %.3f V", *result->battery_voltage);
  }

  return true;
}

bool ATCMiThermometer::decrypt_payload(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address) {
  if (!((raw.size() == 19) || ((raw.size() >= 22) && (raw.size() <= 24)))) {
    ESP_LOGVV(TAG, "decrypt_payload(): data packet has wrong size (%d)!", raw.size());
    ESP_LOGVV(TAG, "  Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());
    return false;
  }

  uint8_t mac_reverse[6] = {0};
  mac_reverse[5] = (uint8_t)(address >> 40);
  mac_reverse[4] = (uint8_t)(address >> 32);
  mac_reverse[3] = (uint8_t)(address >> 24);
  mac_reverse[2] = (uint8_t)(address >> 16);
  mac_reverse[1] = (uint8_t)(address >> 8);
  mac_reverse[0] = (uint8_t)(address >> 0);

  XiaomiAESVector vector{.key = {0},
                         .plaintext = {0},
                         .ciphertext = {0},
                         .authdata = {0x11},
                         .iv = {0},
                         .tag = {0},
                         .keysize = 16,
                         .authsize = 1,
                         .datasize = 0,
                         .tagsize = 4,
                         .ivsize = 12};

  vector.datasize = (raw.size() == 19) ? raw.size() - 12 : raw.size() - 18;
  int cipher_pos = (raw.size() == 19) ? 5 : 11;

  const uint8_t *v = raw.data();

  memcpy(vector.key, bindkey, vector.keysize);
  memcpy(vector.ciphertext, v + cipher_pos, vector.datasize);
  memcpy(vector.tag, v + raw.size() - vector.tagsize, vector.tagsize);
  memcpy(vector.iv, mac_reverse, 6);             // MAC address reverse
  memcpy(vector.iv + 6, v + 2, 3);               // sensor type (2) + packet id (1)
  memcpy(vector.iv + 9, v + raw.size() - 7, 3);  // payload counter

  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);

  int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, vector.key, vector.keysize * 8);
  if (ret) {
    ESP_LOGVV(TAG, "decrypt_xiaomi_payload(): mbedtls_ccm_setkey() failed.");
    mbedtls_ccm_free(&ctx);
    return false;
  }

  ret = mbedtls_ccm_auth_decrypt(&ctx, vector.datasize, vector.iv, vector.ivsize, vector.authdata, vector.authsize,
                                 vector.ciphertext, vector.plaintext, vector.tag, vector.tagsize);
  if (ret) {
    uint8_t mac_address[6] = {0};
    memcpy(mac_address, mac_reverse + 5, 1);
    memcpy(mac_address + 1, mac_reverse + 4, 1);
    memcpy(mac_address + 2, mac_reverse + 3, 1);
    memcpy(mac_address + 3, mac_reverse + 2, 1);
    memcpy(mac_address + 4, mac_reverse + 1, 1);
    memcpy(mac_address + 5, mac_reverse, 1);
    ESP_LOGVV(TAG, "decrypt_xiaomi_payload(): authenticated decryption failed.");
    ESP_LOGVV(TAG, "  MAC address : %s", format_hex_pretty(mac_address, 6).c_str());
    ESP_LOGVV(TAG, "       Packet : %s", format_hex_pretty(raw.data(), raw.size()).c_str());
    ESP_LOGVV(TAG, "          Key : %s", format_hex_pretty(vector.key, vector.keysize).c_str());
    ESP_LOGVV(TAG, "           Iv : %s", format_hex_pretty(vector.iv, vector.ivsize).c_str());
    ESP_LOGVV(TAG, "       Cipher : %s", format_hex_pretty(vector.ciphertext, vector.datasize).c_str());
    ESP_LOGVV(TAG, "          Tag : %s", format_hex_pretty(vector.tag, vector.tagsize).c_str());
    mbedtls_ccm_free(&ctx);
    return false;
  }

  // replace encrypted payload with plaintext
  uint8_t *p = vector.plaintext;
  for (std::vector<uint8_t>::iterator it = raw.begin() + cipher_pos; it != raw.begin() + cipher_pos + vector.datasize;
       ++it) {
    *it = *(p++);
  }

  // clear encrypted flag
  raw[0] &= ~0x08;

  ESP_LOGVV(TAG, "decrypt_payload(): authenticated decryption passed.");
  ESP_LOGVV(TAG, "  Plaintext : %s, Packet : %d", format_hex_pretty(raw.data() + cipher_pos, vector.datasize).c_str(),
            static_cast<int>(raw[4]));

  mbedtls_ccm_free(&ctx);
  return true;
}

void ATCMiThermometer::set_bindkey(const std::string &bindkey) {
  memset(bindkey_, 0, 16);
  if (bindkey.size() != 32) {
    return;
  }
  char temp[3] = {0};
  for (int i = 0; i < 16; i++) {
    strncpy(temp, &(bindkey.c_str()[i * 2]), 2);
    bindkey_[i] = std::strtoul(temp, nullptr, 16);
  }
}


}  // namespace atc_mithermometer
}  // namespace esphome

#endif
