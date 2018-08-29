/**
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
 *
 * @brief
 *
 * @file CommonIO.cpp
 * @author: yujiechen
 * @date 2018-08-29
 */
#include <libdevcore/CommonIO.h>
#include <libdevcore/Exceptions.h>
#include <test/tools/libutils/TestOutputHelper.h>
#include <boost/test/unit_test.hpp>
#include <iostream>
using namespace dev;
using namespace std;
namespace dev
{
namespace test
{
/**
 * @brief Create a file object
 *
 * @param file_path
 * @param content
 */
void create_file(const std::string& file_path, const std::string content)
{
    BOOST_WARN_THROW(writeFile(boost::filesystem::path(file_path), content), FileError);
}
/**
 * @brief
 *
 * @param file_path
 * @param max_try
 */
bool remove_files(const std::string& file_path, unsigned int max_retry = 10)
{
    boost::system::error_code err;
    bool result = boost::filesystem::remove(file_path, err);
    unsigned retry = 0;
    while (result == false && retry < max_retry)
    {
        result = boost::filesystem::remove(file_path, err);
        retry++;
    }
    return result;
}


void testWriteFile(const std::string& file_dir, const std::string& content, unsigned int size)
{
    std::string file_name;
    for (unsigned int i = 0; i < size; i++)
    {
        stringstream ss;
        ss << i;
        file_name = file_dir + "/" + ss.str() + ".txt";
        create_file(file_name, content);
        BOOST_CHECK(boost::filesystem::exists(file_name));
        // test content
        BOOST_CHECK(contents(file_name) == asBytes(content));
        // test contentsString
        BOOST_CHECK(contentsString(file_name) == content);
        // test contentsSec
        contentsSec(file_name);
    }
}

// test writeFile, content and contentsString
BOOST_FIXTURE_TEST_SUITE(CommonIOTest, TestOutputHelperFixture)
BOOST_AUTO_TEST_CASE(testFileOptions)
{
    std::string content = "hello, write file test!";
    std::string file_dir = "tmp/";
    std::string dst_dir = "tmp/test_data";
    std::string file_name;
    unsigned int size = 10;
    testWriteFile(file_dir, content, size);
    // test copyDirectory
    BOOST_WARN_THROW(copyDirectory(file_dir, dst_dir), boost::filesystem::filesystem_error);
    for (unsigned i = 0; i < size; i++)
    {
        stringstream ss;
        ss << i;
        file_name = dst_dir + "/" + ss.str() + ".txt";
        BOOST_CHECK(boost::filesystem::exists(file_name));
        BOOST_CHECK(contentsString(file_name) == content);
    }
    remove_files(file_dir);
    remove_files(dst_dir);
}

BOOST_AUTO_TEST_CASE(testToString) {}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace test
}  // namespace dev
