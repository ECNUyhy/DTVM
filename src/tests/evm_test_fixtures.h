// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TESTS_EVM_TEST_FIXTURES_H
#define ZEN_TESTS_EVM_TEST_FIXTURES_H

#include "evmc/mocked_host.hpp"

#include <memory>
#include <rapidjson/document.h>
#include <string>
#include <vector>

namespace zen::evm_test_utils {

struct ParsedAccount {
  evmc::address Address;
  evmc::MockedAccount Account;
};

struct ParsedTransaction {
  evmc_tx_context TxContext;
  std::unique_ptr<evmc_message> Message;
  std::vector<uint8_t> CallData;
};

struct StateTestFixture {
  std::string TestName;
  std::vector<ParsedAccount> PreState;
  evmc_tx_context Environment;
  std::unique_ptr<rapidjson::Document> Transaction;
  std::unique_ptr<rapidjson::Document> Post;

  StateTestFixture() = default;
  StateTestFixture(const StateTestFixture &) = delete;
  StateTestFixture &operator=(const StateTestFixture &) = delete;
  StateTestFixture(StateTestFixture &&) = default;
  StateTestFixture &operator=(StateTestFixture &&) = default;
};

struct ForkPostResult {
  std::string ExpectedHash;
  std::string ExpectedLogs;
  std::string ExpectedException;
  std::vector<uint8_t> ExpectedTxBytes;
  struct {
    size_t Data = 0;
    size_t Gas = 0;
    size_t Value = 0;
  } Indexes;
  std::shared_ptr<rapidjson::Document> ExpectedState;
};

evmc::address parseAddress(const std::string &HexAddr);
evmc::bytes32 parseBytes32(const std::string &HexStr);
evmc::uint256be parseUint256(const std::string &HexStr);
std::vector<uint8_t> parseHexData(const std::string &HexStr);

std::vector<ParsedAccount> parsePreAccounts(const rapidjson::Value &Pre);

std::vector<std::string> findJsonFiles(const std::string &RootPath);
std::vector<StateTestFixture> parseStateTestFile(const std::string &FilePath);

ForkPostResult parseForkPostResult(const rapidjson::Value &PostResult);
ParsedTransaction
createTransactionFromIndex(const rapidjson::Document &Transaction,
                           const ForkPostResult &Result);

} // namespace zen::evm_test_utils

#endif // ZEN_TESTS_EVM_TEST_FIXTURES_H
