// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H
#define ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H

#include <cstdint>

namespace zen::runtime {

struct EVMMemorySpecializationProfile {
  uint8_t SkipLeadingZeroLimbStores = 0;
  bool HasFullCallDataLoad0Window = false;
  bool HasKnownCallDataLoad0Low64 = false;
  uint64_t KnownCallDataLoad0Low64 = 0;
};

} // namespace zen::runtime

#endif // ZEN_RUNTIME_EVM_MEMORY_SPECIALIZATION_H
