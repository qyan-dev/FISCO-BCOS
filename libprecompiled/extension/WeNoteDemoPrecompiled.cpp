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
 * (c) 2016-2019 fisco-dev contributors.
 */
/** @file WeNoteDemoPrecompiled.cpp
 *  @author qyan
 *  @date 2019
 */
#include "WeNoteDemoPrecompiled.h"
#include "../precompile.h"
#include <libblockverifier/ExecutiveContext.h>
#include <libdevcore/easylog.h>
#include <libethcore/ABI.h>
#include <libethcore/Exceptions.h>
#include <libstorage/EntriesPrecompiled.h>
#include <libstorage/TableFactoryPrecompiled.h>
// #include <inttypes.h>

using namespace dev;
using namespace dev::blockverifier;
using namespace dev::precompiled;
using namespace dev::storage;

/*
contract WeNoteDemoPrecompiled {
    function init();
    function getCreditId() public returns(string);
    function viewCreditId() public view returns(string);

    function queryCredit(string credit_commitment) public view returns(uint256);
    function queryCredit2(
        string credit_commitment, string credit_id) public view returns(string);

    function issueCredit(
        string credit_commitment,
        string credit_id,
        string issuer_info,
        string transaction_time,
        string encrypted_transaction_info);

    function fulfillCredit(
            string credit_commitment,
            string credit_id,
            string transaction_time,
            string encrypted_transaction_info);

    function transferCredit(
            string credit_commitment_1,
            string credit_id_1,
            string credit_commitment_2,
            string credit_id_2,
            string issuer_info_2,
            string transaction_time,
            string encrypted_transaction_info);

    function splitCredit(
            string credit_commitment_1,
            string credit_id_1,
            string credit_commitment_2,
            string credit_id_2,
            string issuer_info_2,
            string credit_commitment_3,
            string credit_id_3,
            string issuer_info_3,
            string transaction_time,
            string encrypted_transaction_info);

    function verifyAndSecureCredit(
            string credit_commitment,
            string credit_id,
            string issuer_info,
            string proof_of_knowledge,
            string transaction_time,
            string encrypted_owner_info,
            string recovery_info);
}
*/

namespace
{
// API signature list.
const char API_INIT[] = "init()";
const char API_GET_CREDIT_ID[] = "getCreditId()";
const char API_VIEW_CREDIT_ID[] = "viewCreditId()";
const char API_QUERY_CREDIT[] = "queryCredit(string)";
const char API_QUERY_CREDIT2[] = "queryCredit2(string,string)";
const char API_ISSUE_CREDIT[] = "issueCredit(string,string,string,string,string)";
const char API_FULFILL_CREDIT[] = "fulfillCredit(string,string,string,string)";
const char API_TRANSFER_CREDIT[] =
    "transferCredit(string,string,string,string,string,string,string)";
const char API_SPLIT_CREDIT[] =
    "splitCredit(string,string,string,string,string,string,string,string,string,string)";
const char API_VERIFY_AND_SECURE_CREDIT[] =
    "verifyAndSecureCredit(string,string,string,string,string,string,string)";

// Table spec list.
const char TABLE_UNSPENT[] = "_ext_wn_unspent_";
const char UNSPENT_KEY[] = "credit_commitment";
const char UNSPENT_VALUES[] = "credit_id,issuer_info";

const char TABLE_SPENT[] = "_ext_wn_spent_";
const char SPENT_KEY[] = "credit_commitment";
const char SPENT_VALUES[] = "credit_id";

const char TABLE_TRANSACTION[] = "_ext_wn_transaction_";
const char TRANSACTION_KEY[] = "transaction_time";
const char TRANSACTION_VALUES[] = "encrypted_transaction_info";

const char TABLE_RECOVERY[] = "_ext_wn_recovery_";
const char RECOVERY_KEY[] = "credit_commitment";
const char RECOVERY_VALUES[] = "credit_id,transaction_time,encrypted_owner_info,recovery_info";

const char TABLE_CONFIG[] = "_ext_wn_config_";
const char CONFIG_KEY[] = "config_key";
const char CONFIG_VALUES[] = "config_value";
const char CONFIG_NEXT_CREDIT_ID[] = "next_credit_id";

const char FIELD_CONFIG_VALUE[] = "config_value";
const char FIELD_CREDIT_ID[] = "credit_id";
const char FIELD_ISSUER_INFO[] = "issuer_info";
const char FIELD_ENCRYPTED_OWNER_INFO[] = "encrypted_owner_info";
const char FIELD_ENCRYPTED_TRANSACTION_INFO[] = "encrypted_transaction_info";
const char FIELD_RECOVERY_INFO[] = "recovery_info";
const char FIELD_TRANSACTION_TIME[] = "transaction_time";

// Other constants
const char CONTRACT_NAME[] = "WeNoteDemoPrecompiled";
const char NO_SIGNATURE[] = "";
const char EMPTY_VALUE[] = "";

void logError(const std::string& _op, const std::string& _msg)
{
    PRECOMPILED_LOG(ERROR) << LOG_BADGE(CONTRACT_NAME) << LOG_DESC(_op) << ": " << LOG_DESC(_msg);
}

void logError(const std::string& _op, const std::string& _key, const std::string& _value)
{
    PRECOMPILED_LOG(ERROR) << LOG_BADGE(CONTRACT_NAME) << LOG_DESC(_op) << LOG_KV(_key, _value);
}

#define RETURN_ON_ERROR(ERROR, FUNC_CALL) \
    ERROR = FUNC_CALL;                    \
    if (!ERROR.empty())                   \
    {                                     \
        return ERROR;                     \
    }

#define RETURN_ON_ERROR2(ERROR, FUNC_CALL) \
    FUNC_CALL;                             \
    if (!ERROR.empty())                    \
    {                                      \
        return ERROR;                      \
    }

#define GET_OUTPUT(VALUE) m_abi.abiIn(NO_SIGNATURE, VALUE)

}  // namespace

WeNoteDemoPrecompiled::WeNoteDemoPrecompiled()
{
    name2Selector[API_INIT] = getFuncSelector(API_INIT);
    name2Selector[API_GET_CREDIT_ID] = getFuncSelector(API_GET_CREDIT_ID);
    name2Selector[API_VIEW_CREDIT_ID] = getFuncSelector(API_VIEW_CREDIT_ID);
    name2Selector[API_QUERY_CREDIT] = getFuncSelector(API_QUERY_CREDIT);
    name2Selector[API_QUERY_CREDIT2] = getFuncSelector(API_QUERY_CREDIT2);
    name2Selector[API_ISSUE_CREDIT] = getFuncSelector(API_ISSUE_CREDIT);
    name2Selector[API_FULFILL_CREDIT] = getFuncSelector(API_FULFILL_CREDIT);
    name2Selector[API_TRANSFER_CREDIT] = getFuncSelector(API_TRANSFER_CREDIT);
    name2Selector[API_SPLIT_CREDIT] = getFuncSelector(API_SPLIT_CREDIT);
    name2Selector[API_VERIFY_AND_SECURE_CREDIT] = getFuncSelector(API_VERIFY_AND_SECURE_CREDIT);
}

bytes WeNoteDemoPrecompiled::call(dev::blockverifier::ExecutiveContext::Ptr _context,
    bytesConstRef _param, const Address& _origin)
{
    bytes out;
    // Parse function name.
    uint32_t func = getParamFunc(_param);
    bytesConstRef data = getParamData(_param);

    if (func == name2Selector[API_INIT])
    {
        init(_origin, _context);
    }
    else if (func == name2Selector[API_GET_CREDIT_ID])
    {
        out = getCreditId(_origin, _context);
    }
    else if (func == name2Selector[API_VIEW_CREDIT_ID])
    {
        out = viewCreditId(_context);
    }
    else if (func == name2Selector[API_QUERY_CREDIT])
    {
        std::string credit_commitment;
        m_abi.abiOut(data, credit_commitment);
        out = queryCredit(credit_commitment, _context);
    }
    else if (func == name2Selector[API_QUERY_CREDIT2])
    {
        std::string credit_commitment;
        std::string credit_id;
        m_abi.abiOut(data, credit_commitment, credit_id);
        out = queryCredit2(credit_commitment, credit_id, _context);
    }
    else if (func == name2Selector[API_ISSUE_CREDIT])
    {
        std::string credit_commitment;
        std::string credit_id;
        std::string issuer_info;
        std::string transaction_time;
        std::string encrypted_transaction_info;
        m_abi.abiOut(data, credit_commitment, credit_id, issuer_info, transaction_time,
            encrypted_transaction_info);
        issueCredit(credit_commitment, credit_id, issuer_info, transaction_time,
            encrypted_transaction_info, _origin, _context);
    }
    else if (func == name2Selector[API_FULFILL_CREDIT])
    {
        std::string credit_commitment;
        std::string credit_id;
        std::string transaction_time;
        std::string encrypted_transaction_info;
        m_abi.abiOut(
            data, credit_commitment, credit_id, transaction_time, encrypted_transaction_info);
        fulfillCredit(credit_commitment, credit_id, transaction_time, encrypted_transaction_info,
            _origin, _context);
    }
    else if (func == name2Selector[API_TRANSFER_CREDIT])
    {
        std::string credit_commitment_1;
        std::string credit_id_1;
        std::string credit_commitment_2;
        std::string credit_id_2;
        std::string issuer_info_2;
        std::string transaction_time;
        std::string encrypted_transaction_info;
        m_abi.abiOut(data, credit_commitment_1, credit_id_1, credit_commitment_2, credit_id_2,
            issuer_info_2, transaction_time, encrypted_transaction_info);
        transferCredit(credit_commitment_1, credit_id_1, credit_commitment_2, credit_id_2,
            issuer_info_2, transaction_time, encrypted_transaction_info, _origin, _context);
    }
    else if (func == name2Selector[API_SPLIT_CREDIT])
    {
        std::string credit_commitment_1;
        std::string credit_id_1;
        std::string credit_commitment_2;
        std::string credit_id_2;
        std::string issuer_info_2;
        std::string credit_commitment_3;
        std::string credit_id_3;
        std::string issuer_info_3;
        std::string transaction_time;
        std::string encrypted_transaction_info;
        m_abi.abiOut(data, credit_commitment_1, credit_id_1, credit_commitment_2, credit_id_2,
            issuer_info_2, credit_commitment_3, credit_id_3, issuer_info_3, transaction_time,
            encrypted_transaction_info);
        splitCredit(credit_commitment_1, credit_id_1, credit_commitment_2, credit_id_2,
            issuer_info_2, credit_commitment_3, credit_id_3, issuer_info_3, transaction_time,
            encrypted_transaction_info, _origin, _context);
    }
    else if (func == name2Selector[API_VERIFY_AND_SECURE_CREDIT])
    {
        std::string credit_commitment;
        std::string credit_id;
        std::string issuer_info;
        std::string proof_of_knowledge;
        std::string transaction_time;
        std::string encrypted_owner_info;
        std::string recovery_info;
        m_abi.abiOut(data, credit_commitment, credit_id, issuer_info, proof_of_knowledge,
            transaction_time, encrypted_owner_info, recovery_info);
        verifyAndSecureCredit(credit_commitment, credit_id, issuer_info, proof_of_knowledge,
            transaction_time, encrypted_owner_info, recovery_info, _origin, _context);
    }
    else
    {  // unknown function call
        logError("*unknown func*", "func", std::to_string(func));
        throwException("*unknown func*");
    }
    return out;
}

void WeNoteDemoPrecompiled::init(
    const Address& _origin, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    createTableOrDie(TABLE_UNSPENT, UNSPENT_KEY, UNSPENT_VALUES, _origin, _context);
    createTableOrDie(TABLE_SPENT, SPENT_KEY, SPENT_VALUES, _origin, _context);
    createTableOrDie(TABLE_TRANSACTION, TRANSACTION_KEY, TRANSACTION_VALUES, _origin, _context);
    createTableOrDie(TABLE_RECOVERY, RECOVERY_KEY, RECOVERY_VALUES, _origin, _context);
    createTableOrDie(TABLE_CONFIG, CONFIG_KEY, CONFIG_VALUES, _origin, _context);
    logError("init", "Succeeded.");
}

bytes WeNoteDemoPrecompiled::getCreditId(
    const Address& _origin, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table = openTableOrDie(TABLE_CONFIG, _context);

    // Fetch existing value if possible.
    auto entries = table->select(CONFIG_NEXT_CREDIT_ID, table->newCondition());
    uint64_t next_credit_id = 0;
    bool first_call = true;

    if (entries->size() == 1)
    {
        auto entry = entries->get(0);
        next_credit_id = std::stol(entry->getField(FIELD_CONFIG_VALUE));
        first_call = false;
    }
    else if (entries->size() > 1)
    {
        throwException("Unexpected multiple next_credit_id value.");
    }

    ++next_credit_id;
    std::string next_credit_id_str = std::to_string(next_credit_id);

    // Store updated value.
    auto entry = table->newEntry();
    entry->setField(FIELD_CONFIG_VALUE, next_credit_id_str);

    int count;
    if (first_call)
    {
        count =
            table->insert(CONFIG_NEXT_CREDIT_ID, entry, std::make_shared<AccessOptions>(_origin));
    }
    else
    {
        count = table->update(CONFIG_NEXT_CREDIT_ID, entry, table->newCondition(),
            std::make_shared<AccessOptions>(_origin));
    }

    if (count != 1)
    {
        throwException("Failed to update next_credit_id value.");
    }
    logError("getCreditId", "Got credit id", next_credit_id_str);
    return GET_OUTPUT(next_credit_id_str);
}

bytes WeNoteDemoPrecompiled::viewCreditId(
    std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table = openTableOrDie(TABLE_CONFIG, _context);
    auto entries = table->select(CONFIG_NEXT_CREDIT_ID, table->newCondition());
    if (entries->size() != 1)
    {
        throwException("Invalid internal status for CreditId.");
    }
    return GET_OUTPUT(entries->get(0)->getField(FIELD_CONFIG_VALUE));
}

bytes WeNoteDemoPrecompiled::queryCredit(const std::string& _credit_commitment,
    std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table = openTableOrDie(TABLE_UNSPENT, _context);

    auto entries = fetchWithCommitment(_credit_commitment, table);
    logError("queryCredit", "Found some credit", std::to_string(entries->size() > 0));
    return GET_OUTPUT(u256(entries->size() > 0));
}

bytes WeNoteDemoPrecompiled::queryCredit2(const std::string& _credit_commitment,
    const std::string& _credit_id, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table = openTableOrDie(TABLE_UNSPENT, _context);
    auto entries = fetchWithCommitmentAndId(_credit_commitment, _credit_id, table);

    if (entries->size() > 1)
    {
        throwException("Unexpected multiple credit_id for the same commitment.");
    }

    std::string issuer_info = EMPTY_VALUE;
    if (entries->size() == 1)
    {
        auto entry = entries->get(0);
        issuer_info = entry->getField(FIELD_ISSUER_INFO);
    }
    logError("queryCredit2", "Found credit's issuer", issuer_info);
    return GET_OUTPUT(issuer_info);
}

void WeNoteDemoPrecompiled::issueCredit(const std::string& _credit_commitment,
    const std::string& _credit_id, const std::string& _issuer_info,
    const std::string& _transaction_time, const std::string& _encrypted_transaction_info,
    const Address& _origin, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    verifyIssuerInfo2(_issuer_info, _origin);

    Table::Ptr table;
    // Add record to t_unspent.
    table = openTableOrDie(TABLE_UNSPENT, _context);
    auto entries = fetchWithCommitmentAndId(_credit_commitment, _credit_id, table);
    if (entries->size() > 0)
    {
        throwException("Credit already exists.");
    }
    appendCreditRecord(_credit_commitment, _credit_id, _issuer_info, _origin, table);

    // Add record to t_transaction.
    table = openTableOrDie(TABLE_TRANSACTION, _context);
    appendTransactionInfo(_transaction_time, _encrypted_transaction_info, _origin, table);
    logError("issueCredit", "Succeeded.");
}

void WeNoteDemoPrecompiled::fulfillCredit(const std::string& _credit_commitment,
    const std::string& _credit_id, const std::string& _transaction_time,
    const std::string& _encrypted_transaction_info, const Address& _origin,
    std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table;
    // Delete old credit.
    table = openTableOrDie(TABLE_UNSPENT, _context);

    auto entries = fetchExactlyOneWithCommitmentAndId(_credit_commitment, _credit_id, table);
    // This credit must be signed by the bank of _origin.
    verifyIssuerInfo2(entries->get(0)->getField(FIELD_ISSUER_INFO), _origin);
    deleteCreditRecord(_credit_commitment, _credit_id, _origin, table);

    // Add record to t_spent.
    table = openTableOrDie(TABLE_SPENT, _context);
    appendSpentRecord(_credit_commitment, _credit_id, _origin, table);

    // Delete recovery record.
    table = openTableOrDie(TABLE_RECOVERY, _context);
    deleteRecoveryInfo(_credit_commitment, _credit_id, _origin, table);

    // Add record to t_transaction.
    table = openTableOrDie(TABLE_TRANSACTION, _context);
    appendTransactionInfo(_transaction_time, _encrypted_transaction_info, _origin, table);
    logError("fulfillCredit", "Succeeded.");
}

void WeNoteDemoPrecompiled::transferCredit(const std::string& _credit_commitment_1,
    const std::string& _credit_id_1, const std::string& _credit_commitment_2,
    const std::string& _credit_id_2, const std::string& _issuer_info_2,
    const std::string& _transaction_time, const std::string& _encrypted_transaction_info,
    const Address& _origin, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    verifyIssuerInfo(_issuer_info_2);

    Table::Ptr table;
    // Delete old credit.
    table = openTableOrDie(TABLE_UNSPENT, _context);
    deleteExactlyOneCreditRecord(_credit_commitment_1, _credit_id_1, _origin, table);
    // Add credit_commitment_2.
    appendCreditRecord(_credit_commitment_2, _credit_id_2, _issuer_info_2, _origin, table);

    // Add credit_commitment_1 to t_spent.
    table = openTableOrDie(TABLE_SPENT, _context);
    appendSpentRecord(_credit_commitment_1, _credit_id_1, _origin, table);

    // Delete recovery record of credit_commitment_1.
    table = openTableOrDie(TABLE_RECOVERY, _context);
    deleteRecoveryInfo(_credit_commitment_1, _credit_id_1, _origin, table);

    // Add record to t_transaction.
    table = openTableOrDie(TABLE_TRANSACTION, _context);
    appendTransactionInfo(_transaction_time, _encrypted_transaction_info, _origin, table);
    logError("transferCredit", "Succeeded.");
}

void WeNoteDemoPrecompiled::splitCredit(const std::string& _credit_commitment_1,
    const std::string& _credit_id_1, const std::string& _credit_commitment_2,
    const std::string& _credit_id_2, const std::string& _issuer_info_2,
    const std::string& _credit_commitment_3, const std::string& _credit_id_3,
    const std::string& _issuer_info_3, const std::string& _transaction_time,
    const std::string& _encrypted_transaction_info, const Address& _origin,
    std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    verifyIssuerInfo(_issuer_info_2);
    verifyIssuerInfo(_issuer_info_3);

    Table::Ptr table;
    // Delete old credit.
    table = openTableOrDie(TABLE_UNSPENT, _context);
    deleteExactlyOneCreditRecord(_credit_commitment_1, _credit_id_1, _origin, table);
    // Add credit_commitment_2.
    appendCreditRecord(_credit_commitment_2, _credit_id_2, _issuer_info_2, _origin, table);
    // Add credit_commitment_3.
    appendCreditRecord(_credit_commitment_3, _credit_id_3, _issuer_info_3, _origin, table);

    // Add credit_commitment_1 to t_spent.
    table = openTableOrDie(TABLE_SPENT, _context);
    appendSpentRecord(_credit_commitment_1, _credit_id_1, _origin, table);

    // Delete recovery record of credit_commitment_1.
    table = openTableOrDie(TABLE_RECOVERY, _context);
    deleteRecoveryInfo(_credit_commitment_1, _credit_id_1, _origin, table);

    // Add record to t_transaction.
    table = openTableOrDie(TABLE_TRANSACTION, _context);
    appendTransactionInfo(_transaction_time, _encrypted_transaction_info, _origin, table);
    logError("splitCredit", "Succeeded.");
}

void WeNoteDemoPrecompiled::verifyAndSecureCredit(const std::string& _credit_commitment,
    const std::string& _credit_id, const std::string& _issuer_info,
    const std::string& _proof_of_knowledge, const std::string& _transaction_time,
    const std::string& _encrypted_owner_info, const std::string& _recovery_info,
    const Address& _origin, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    verifyProofOfKnowledge(_credit_commitment, _proof_of_knowledge);

    Table::Ptr table;

    // Check the presence of credit_commitment.
    table = openTableOrDie(TABLE_UNSPENT, _context);
    auto entries = fetchExactlyOneWithCommitmentAndId(_credit_commitment, _credit_id, table);

    auto entry = entries->get(0);
    std::string stored_issuer_info = entry->getField(FIELD_ISSUER_INFO);
    if (_issuer_info != stored_issuer_info)
    {
        throwException("Issuer info does not match.");
    }

    // Add record to t_recovery.
    table = openTableOrDie(TABLE_RECOVERY, _context);
    appendRecoveryInfo(_credit_commitment, _credit_id, _transaction_time, _encrypted_owner_info,
        _recovery_info, _origin, table);
    logError("verifyAndSecureCredit", "Succeeded.");
}

// Utility functions.
void WeNoteDemoPrecompiled::createTableOrDie(const std::string& _table_name,
    const std::string& _key_field, const std::string& _value_fields, const Address& _origin,
    std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    Table::Ptr table = openTable(_context, _table_name);
    if (table)
    {
        throwException("Table already exists.");
    }

    table = createTable(_context, _table_name, _key_field, _value_fields, _origin);
    if (!table)
    {
        throwException("Creating table failed.");
    }
}

dev::storage::Table::Ptr WeNoteDemoPrecompiled::openTableOrDie(
    const std::string& _table_name, std::shared_ptr<dev::blockverifier::ExecutiveContext> _context)
{
    auto table = openTable(_context, _table_name);
    if (!table)
    {
        throwException("Table does not exist.");
    }
    return table;
}

dev::storage::Entries::ConstPtr WeNoteDemoPrecompiled::fetchWithCommitmentAndId(
    const std::string& _credit_commitment, const std::string& _credit_id,
    dev::storage::Table::Ptr _table)
{
    auto condition = _table->newCondition();
    condition->EQ(FIELD_CREDIT_ID, _credit_id);
    return _table->select(_credit_commitment, condition);
}

dev::storage::Entries::ConstPtr WeNoteDemoPrecompiled::fetchExactlyOneWithCommitmentAndId(
    const std::string& _credit_commitment, const std::string& _credit_id,
    dev::storage::Table::Ptr _table)
{
    auto entries = fetchWithCommitmentAndId(_credit_commitment, _credit_id, _table);
    if (entries->size() == 0)
    {
        throwException("Credit does not exists.");
    }
    if (entries->size() > 1)
    {
        throwException("Unexpected multiple copies of the same credit.");
    }
    return entries;
}

dev::storage::Entries::ConstPtr WeNoteDemoPrecompiled::fetchWithCommitment(
    const std::string& _credit_commitment, dev::storage::Table::Ptr _table)
{
    auto condition = _table->newCondition();
    return _table->select(_credit_commitment, condition);
}

void WeNoteDemoPrecompiled::appendCreditRecord(const std::string& _credit_commitment,
    const std::string& _credit_id, const std::string& _issuer_info, const Address& _origin,
    dev::storage::Table::Ptr _table)
{
    auto entry = _table->newEntry();
    entry->setField(FIELD_CREDIT_ID, _credit_id);
    entry->setField(FIELD_ISSUER_INFO, _issuer_info);
    int count = _table->insert(_credit_commitment, entry, std::make_shared<AccessOptions>(_origin));
    if (count != 1)
    {
        throwException("Failed to append new credit.");
    }
    logError("appendCreditRecord", "Added a new credit.");
}

void WeNoteDemoPrecompiled::appendSpentRecord(const std::string& _credit_commitment,
    const std::string& _credit_id, const Address& _origin, dev::storage::Table::Ptr _table)
{
    auto entry = _table->newEntry();
    entry->setField(FIELD_CREDIT_ID, _credit_id);
    int count = _table->insert(_credit_commitment, entry, std::make_shared<AccessOptions>(_origin));
    if (count != 1)
    {
        throwException("Failed to append spent credit.");
    }
    logError("appendSpentRecord", "Added a spent record.");
}

void WeNoteDemoPrecompiled::appendTransactionInfo(const std::string& _transaction_time,
    const std::string& _encrypted_transaction_info, const Address& _origin,
    dev::storage::Table::Ptr _table)
{
    auto entry = _table->newEntry();
    entry->setField(FIELD_ENCRYPTED_TRANSACTION_INFO, _encrypted_transaction_info);
    int count = _table->insert(_transaction_time, entry, std::make_shared<AccessOptions>(_origin));
    if (count != 1)
    {
        throwException("Failed to append transaction info.");
    }
    logError("appendTransactionInfo", "Added a transaction info.");
}

void WeNoteDemoPrecompiled::appendRecoveryInfo(const std::string& _credit_commitment,
    const std::string& _credit_id, const std::string& _transaction_time,
    const std::string& _encrypted_owner_info, const std::string& _recovery_info,
    const Address& _origin, dev::storage::Table::Ptr _table)
{
    auto entry = _table->newEntry();
    entry->setField(FIELD_CREDIT_ID, _credit_id);
    entry->setField(FIELD_TRANSACTION_TIME, _transaction_time);
    entry->setField(FIELD_ENCRYPTED_OWNER_INFO, _encrypted_owner_info);
    entry->setField(FIELD_RECOVERY_INFO, _recovery_info);
    int count = _table->insert(_credit_commitment, entry, std::make_shared<AccessOptions>(_origin));
    if (count != 1)
    {
        throwException("Failed to append recovery info.");
    }
    logError("appendRecoveryInfo", "Added a recovery info.");
}

void WeNoteDemoPrecompiled::deleteCreditRecord(const std::string& _credit_commitment,
    const std::string& _credit_id, const Address& _origin, dev::storage::Table::Ptr _table)
{
    auto condition = _table->newCondition();
    condition->EQ(FIELD_CREDIT_ID, _credit_id);
    int count =
        _table->remove(_credit_commitment, condition, std::make_shared<AccessOptions>(_origin));
    if (count == 0)
    {
        throwException("Failed to delete existing credit.");
    }
    logError("deleteCreditRecord", "Deleted existing credits.");
}

void WeNoteDemoPrecompiled::deleteExactlyOneCreditRecord(const std::string& _credit_commitment,
    const std::string& _credit_id, const Address& _origin, dev::storage::Table::Ptr _table)
{
    fetchExactlyOneWithCommitmentAndId(_credit_commitment, _credit_id, _table);
    deleteCreditRecord(_credit_commitment, _credit_id, _origin, _table);
}

void WeNoteDemoPrecompiled::deleteRecoveryInfo(const std::string& _credit_commitment,
    const std::string& _credit_id, const Address& _origin, dev::storage::Table::Ptr _table)
{
    auto condition = _table->newCondition();
    condition->EQ(FIELD_CREDIT_ID, _credit_id);
    int count =
        _table->remove(_credit_commitment, condition, std::make_shared<AccessOptions>(_origin));
    if (count == 0)
    {
        throwException("Failed to delete recovery info.");
    }
    logError("deleteRecoveryInfo", "Deleted recovery infos.");
}

void WeNoteDemoPrecompiled::verifyIssuerInfo(const std::string& _issuer_info)
{
    // TODO: Make it real.
    if (_issuer_info.empty())
    {
        throwException("Invalid issuer info.");
    }
}

void WeNoteDemoPrecompiled::verifyIssuerInfo2(
    const std::string& _issuer_info, const Address& _origin)
{
    // TODO: Make it real.
    if (_issuer_info.empty() || _origin.asBytes().empty())
    {
        throwException("Invalid issuer info for corresponding origin.");
    }
}

void WeNoteDemoPrecompiled::verifyProofOfKnowledge(
    const std::string& _credit_commitment, const std::string& _proof_of_knowledge)
{
    // TODO: Make it real.
    if (_credit_commitment.empty() || _proof_of_knowledge.empty())
    {
        throwException("Invalid proof of knowledge.");
    }
    // #ifdef __cplusplus
    // extern "C"
    // {
    // #endif
    std::string s_z0 = "fe53d15388639fc8e07a6a81d5c62412b5d828d66fd5412309f31f9ab13b8d05";
    char* z0 = new char[s_z0.length() + 1];
    strcpy(z0, s_z0.c_str());
    std::string s_z1 = "0b3fe249c7624a8a1f699e2ad4606112f9c90541c5e8f8a26d3391a820033409";
    char* z1 = new char[s_z1.length() + 1];
    strcpy(z0, s_z1.c_str());
    std::string s_z2 = "fe53d15388639fc8e07a6a81d5c62412b5d828d66fd5412309f31f9ab13b8d05";
    char* z2 = new char[s_z2.length() + 1];
    strcpy(z2, s_z2.c_str());
    std::string s_cc = "de899dfb10dc0e1f1ecf93cf53fec4ea1081b66dbbfe4164ea4f80eaf1a7343e";
    char* cc = new char[s_cc.length() + 1];
    strcpy(cc, s_cc.c_str());
    std::string s_tx_time = "good!";
    char* tx_time = new char[s_tx_time.length() + 1];
    strcpy(tx_time, s_tx_time.c_str());
    // char const *z0 = "fe53d15388639fc8e07a6a81d5c62412b5d828d66fd5412309f31f9ab13b8d05";
    // char const *z1 = "0b3fe249c7624a8a1f699e2ad4606112f9c90541c5e8f8a26d3391a820033409";
    // char const *z2 = "c6a02bc3528e70d6bf8105dcb63257ee3f75b53c2b9d935cfb85c3cae7777607";
    // char const *cc = "de899dfb10dc0e1f1ecf93cf53fec4ea1081b66dbbfe4164ea4f80eaf1a7343e";
    // char const *tx_time = "good!";
    char* result = knowledge_verify(z0, z1, z2, cc, tx_time);
    printf("now result is %s\n", result);
    // delete [] z0;
    // #ifdef __cplusplus
    // }
    // #endif
}

void WeNoteDemoPrecompiled::throwException(const std::string& msg)
{
    BOOST_THROW_EXCEPTION(dev::eth::TransactionRefused() << errinfo_comment(msg));
    // No idea how to construct it.
    // throw dev::eth::RevertInstruction();
}