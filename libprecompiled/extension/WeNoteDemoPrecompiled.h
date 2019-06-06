/*
 * @CopyRight:
 * FISCO-BCOS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FISCO-BCOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>
 * (c) 2016-2018 fisco-dev contributors.
 */
/** @file WeNoteDemoPrecompiled.h
 *  @author qyan
 *  @date 2019
 */
#pragma once
#include <libprecompiled/Common.h>
#include <libethcore/ABI.h>

namespace dev
{
namespace precompiled
{
class WeNoteDemoPrecompiled : public dev::blockverifier::Precompiled
{
  public:
    typedef std::shared_ptr<WeNoteDemoPrecompiled> Ptr;
    WeNoteDemoPrecompiled();

    virtual bytes call(std::shared_ptr<dev::blockverifier::ExecutiveContext> _context,
        bytesConstRef _param, const Address& _origin = Address()) override;

  private:
    // API functions.
    void init(
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    bytes getCreditId(
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    bytes queryCredit(
        const std::string& _credit_commitment,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    bytes queryCredit2(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    void issueCredit(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const std::string& _issuer_info,
        const std::string& _transaction_time,
        const std::string& _encrypted_transaction_info,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    void fulfillCredit(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const std::string& _transaction_time,
        const std::string& _encrypted_transaction_info,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    void transferCredit(
        const std::string& _credit_commitment_1,
        const std::string& _credit_id_1,
        const std::string& _credit_commitment_2,
        const std::string& _credit_id_2,
        const std::string& _issuer_info_2,
        const std::string& _transaction_time,
        const std::string& _encrypted_transaction_info,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    void splitCredit(
        const std::string& _credit_commitment_1,
        const std::string& _credit_id_1,
        const std::string& _credit_commitment_2,
        const std::string& _credit_id_2,
        const std::string& _issuer_info_2,
        const std::string& _credit_commitment_3,
        const std::string& _credit_id_3,
        const std::string& _issuer_info_3,
        const std::string& _transaction_time,
        const std::string& _encrypted_transaction_info,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    void verifyAndSecureCredit(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const std::string& _issuer_info,
        const std::string& _transaction_time,
        const std::string& _encrypted_owner_info,
        const std::string& _recovery_info,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);

    // Utility functions.
    void createTableOrDie(
        const std::string& _table_name,
        const std::string& _key_field,
        const std::string& _value_fields,
        const Address& _origin,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    dev::storage::Table::Ptr openTableOrDie(
        const std::string& _table_name,
        std::shared_ptr<dev::blockverifier::ExecutiveContext> _context);
    dev::storage::Entries::ConstPtr fetchWithCommitmentAndId(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        dev::storage::Table::Ptr _table);
    dev::storage::Entries::ConstPtr fetchWithCommitment(
        const std::string& _credit_commitment,
        dev::storage::Table::Ptr _table);
    dev::storage::Entries::ConstPtr fetchExactlyOneWithCommitmentAndId(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        dev::storage::Table::Ptr _table);
    void appendCreditRecord(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const std::string& _issuer_info,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void appendSpentRecord(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void appendTransactionInfo(
        const std::string& _transaction_time,
        const std::string& _encrypted_transaction_info,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void appendRecoveryInfo(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const std::string& _transaction_time,
        const std::string& _encrypted_owner_info,
        const std::string& _recovery_info,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void deleteCreditRecord(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void deleteExactlyOneCreditRecord(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void deleteRecoveryInfo(
        const std::string& _credit_commitment,
        const std::string& _credit_id,
        const Address& _origin,
        dev::storage::Table::Ptr _table);
    void throwException(const std::string& msg);

    dev::eth::ContractABI m_abi;
};

}  // namespace precompiled

}  // namespace dev