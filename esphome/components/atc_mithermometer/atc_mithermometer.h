#pragma once

#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#include <vector>

#ifdef USE_ESP32

namespace esphome {
namespace atc_mithermometer {

struct ParseResult {
  optional<float> temperature;
  optional<float> humidity;
  optional<float> battery_level;
  optional<float> battery_voltage;
  bool has_encryption;  // 0x08
  int raw_offset;
};

struct XiaomiAESVector {
  uint8_t key[16];
  uint8_t plaintext[16];
  uint8_t ciphertext[16];
  uint8_t authdata[16];
  uint8_t iv[16];
  uint8_t tag[16];
  size_t keysize;
  size_t authsize;
  size_t datasize;
  size_t tagsize;
  size_t ivsize;
};

class ATCMiThermometer : public Component, public esp32_ble_tracker::ESPBTDeviceListener {
 public:
  void set_address(uint64_t address) { address_ = address; };
  void set_bindkey(const std::string &bindkey);

  bool parse_device(const esp32_ble_tracker::ESPBTDevice &device) override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::DATA; }
  void set_temperature(sensor::Sensor *temperature) { temperature_ = temperature; }
  void set_humidity(sensor::Sensor *humidity) { humidity_ = humidity; }
  void set_battery_level(sensor::Sensor *battery_level) { battery_level_ = battery_level; }
  void set_battery_voltage(sensor::Sensor *battery_voltage) { battery_voltage_ = battery_voltage; }
  void set_signal_strength(sensor::Sensor *signal_strength) { signal_strength_ = signal_strength; }

 protected:
  uint64_t address_;
  uint8_t bindkey_[16];
  sensor::Sensor *temperature_{nullptr};
  sensor::Sensor *humidity_{nullptr};
  sensor::Sensor *battery_level_{nullptr};
  sensor::Sensor *battery_voltage_{nullptr};
  sensor::Sensor *signal_strength_{nullptr};

  optional<ParseResult> parse_header_(const esp32_ble_tracker::ServiceData &service_data);
  bool parse_message_(const std::vector<uint8_t> &message, ParseResult &result);
  bool decrypt_payload(std::vector<uint8_t> &raw, const uint8_t *bindkey, const uint64_t &address);
  bool report_results_(const optional<ParseResult> &result, const std::string &address);
};

}  // namespace atc_mithermometer
}  // namespace esphome

#endif
