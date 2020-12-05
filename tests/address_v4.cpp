#include <catch2/catch.hpp>
#include <network/ip/address_v4.hpp>

using network::ip::address_v4;
using std::equal;

const address_v4::bytes_type zero_array{{0, 0, 0, 0}};
const address_v4::bytes_type uno_array{{1, 1, 1, 1}};
const address_v4::bytes_type max_array{{255, 255, 255, 255}};

TEST_CASE("Address can be default constructed", "[address_v4]")
{
	address_v4 addr;

	auto data = addr.to_bytes();

	REQUIRE(equal(zero_array.begin(), zero_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0);
	REQUIRE(addr.to_string() == "0.0.0.0");
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
};

TEST_CASE("Address can be constructed from integer", "[address_v4]")
{
	address_v4 addr(0x01010101);

	auto data = addr.to_bytes();

	REQUIRE(equal(uno_array.begin(), uno_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0x01010101);
	REQUIRE(addr.to_string() == "1.1.1.1");
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
};

TEST_CASE("Address can be constructed from bytes array", "[address_v4]")
{
	address_v4 addr(max_array);

	auto data = addr.to_bytes();

	REQUIRE(equal(max_array.begin(), max_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0xffffffff);
	REQUIRE(addr.to_string() == "255.255.255.255");
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
}

TEST_CASE("Address is copyable", "[address_v4]")
{
	address_v4 addr_copyable(max_array);

	address_v4 addr(addr_copyable);

	auto data = addr.to_bytes();

	REQUIRE(equal(max_array.begin(), max_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0xffffffff);
	REQUIRE(addr.to_uint() == addr_copyable.to_uint());
	REQUIRE(addr.to_string() == "255.255.255.255");
	REQUIRE(addr.to_string() == addr_copyable.to_string());
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
}

TEST_CASE("Address is movable", "[address_v4]")
{
	address_v4 addr_movable(max_array);

	address_v4 addr(std::move(addr_movable));

	auto data		 = addr.to_bytes();
	auto moved_data = addr_movable.to_bytes();

	REQUIRE(equal(max_array.begin(), max_array.end(), data.begin(), data.end()));
	REQUIRE(equal(moved_data.begin(), moved_data.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0xffffffff);
	REQUIRE(addr.to_uint() == addr_movable.to_uint());

	REQUIRE(addr.to_string() == "255.255.255.255");
	REQUIRE(addr.to_string() == addr_movable.to_string());
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
}

TEST_CASE("Address can compare", "[address_v4]")
{
	address_v4 addr1;

	auto addr2 = address_v4::any();
	auto addr3 = address_v4::loopback();
	auto addr4 = address_v4::broadcast();

	REQUIRE(addr1 == addr2);
	REQUIRE(addr1 != addr3);
	REQUIRE(addr1 != addr4);
}

TEST_CASE("Address can be constructed from string", "[address_v4]")
{
	std::string address_string = "127.0.0.1";
	auto addr						= address_v4::from_str(address_string);
	auto data						= addr.to_bytes();

	address_v4::bytes_type data_{{0x7f, 0, 0, 1}};

	REQUIRE(equal(data_.begin(), data_.end(), data.begin(), data.end()));
	REQUIRE(addr.to_uint() == 0x7f000001);
	REQUIRE(addr.to_string() == address_string);
	REQUIRE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE_FALSE(addr.is_unspecified());
}
