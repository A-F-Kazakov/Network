#include <catch2/catch.hpp>
#include <network/ip/address_v6.hpp>

using network::ip::address_v6;
using std::equal;

const address_v6::bytes_type zero_array{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const address_v6::bytes_type loopback_array{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

TEST_CASE("Default constructor", "[address_v6]")
{
	address_v6 addr;

	auto data = addr.to_bytes();

	REQUIRE(equal(zero_array.begin(), zero_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_string() == "::");
	REQUIRE(addr.scope_id() == 0);
	REQUIRE_FALSE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE(addr.is_unspecified());
	REQUIRE_FALSE(addr.is_link_local());
	REQUIRE_FALSE(addr.is_site_local());
	REQUIRE_FALSE(addr.is_v4_mapped());
	REQUIRE_FALSE(addr.is_multicast_global());
	REQUIRE_FALSE(addr.is_multicast_link_local());
	REQUIRE_FALSE(addr.is_multicast_node_local());
	REQUIRE_FALSE(addr.is_multicast_org_local());
	REQUIRE_FALSE(addr.is_multicast_site_local());
}

TEST_CASE("Array constructor", "[address_v6]")
{
	address_v6 addr(loopback_array);

	auto data = addr.to_bytes();

	REQUIRE(equal(loopback_array.begin(), loopback_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_string() == "::1");
	REQUIRE(addr.scope_id() == 0);
	REQUIRE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE_FALSE(addr.is_unspecified());
	REQUIRE_FALSE(addr.is_link_local());
	REQUIRE_FALSE(addr.is_site_local());
	REQUIRE_FALSE(addr.is_v4_mapped());
	REQUIRE_FALSE(addr.is_multicast_global());
	REQUIRE_FALSE(addr.is_multicast_link_local());
	REQUIRE_FALSE(addr.is_multicast_node_local());
	REQUIRE_FALSE(addr.is_multicast_org_local());
	REQUIRE_FALSE(addr.is_multicast_site_local());
}

TEST_CASE("Copy constructor", "[address_v6]")
{
	auto addr = address_v6::loopback();

	address_v6 copied(addr);

	auto data = copied.to_bytes();

	REQUIRE(equal(loopback_array.begin(), loopback_array.end(), data.begin(), data.end()));
	REQUIRE(copied.to_string() == "::1");
	REQUIRE(copied.is_loopback());
	REQUIRE_FALSE(copied.is_multicast());
	REQUIRE_FALSE(copied.is_unspecified());
	REQUIRE_FALSE(copied.is_multicast());
	REQUIRE_FALSE(copied.is_unspecified());
	REQUIRE_FALSE(copied.is_link_local());
	REQUIRE_FALSE(copied.is_site_local());
	REQUIRE_FALSE(copied.is_v4_mapped());
	REQUIRE_FALSE(copied.is_multicast_global());
	REQUIRE_FALSE(copied.is_multicast_link_local());
	REQUIRE_FALSE(copied.is_multicast_node_local());
	REQUIRE_FALSE(copied.is_multicast_org_local());
	REQUIRE_FALSE(copied.is_multicast_site_local());
}

TEST_CASE("Move constructor", "[address_v6]")
{
	auto addr = address_v6::loopback();

	address_v6 moved(std::move(addr));

	auto data = moved.to_bytes();

	REQUIRE(equal(loopback_array.begin(), loopback_array.end(), data.begin(), data.end()));
	REQUIRE(moved.to_string() == "::1");
	REQUIRE(moved.is_loopback());
	REQUIRE_FALSE(moved.is_multicast());
	REQUIRE_FALSE(moved.is_unspecified());
	REQUIRE_FALSE(moved.is_multicast());
	REQUIRE_FALSE(moved.is_unspecified());
	REQUIRE_FALSE(moved.is_link_local());
	REQUIRE_FALSE(moved.is_site_local());
	REQUIRE_FALSE(moved.is_v4_mapped());
	REQUIRE_FALSE(moved.is_multicast_global());
	REQUIRE_FALSE(moved.is_multicast_link_local());
	REQUIRE_FALSE(moved.is_multicast_node_local());
	REQUIRE_FALSE(moved.is_multicast_org_local());
	REQUIRE_FALSE(moved.is_multicast_site_local());
}

TEST_CASE("Copy assign operator", "[address_v6]")
{
	auto addr = address_v6::any();

	address_v6 copied;

	copied = addr;

	auto data = copied.to_bytes();

	REQUIRE(equal(zero_array.begin(), zero_array.end(), data.begin(), data.end()));
	REQUIRE(copied.to_string() == "::");
	REQUIRE_FALSE(copied.is_loopback());
	REQUIRE_FALSE(copied.is_multicast());
	REQUIRE(copied.is_unspecified());
	REQUIRE_FALSE(copied.is_multicast());
	REQUIRE_FALSE(copied.is_link_local());
	REQUIRE_FALSE(copied.is_site_local());
	REQUIRE_FALSE(copied.is_v4_mapped());
	REQUIRE_FALSE(copied.is_multicast_global());
	REQUIRE_FALSE(copied.is_multicast_link_local());
	REQUIRE_FALSE(copied.is_multicast_node_local());
	REQUIRE_FALSE(copied.is_multicast_org_local());
	REQUIRE_FALSE(copied.is_multicast_site_local());
}

TEST_CASE("Move assign operator", "[address_v6]")
{
	auto addr = address_v6::any();

	address_v6 moved;

	moved = std::move(addr);

	auto data = moved.to_bytes();

	REQUIRE(equal(zero_array.begin(), zero_array.end(), data.begin(), data.end()));
	REQUIRE(moved.to_string() == "::");
	REQUIRE_FALSE(moved.is_loopback());
	REQUIRE_FALSE(moved.is_multicast());
	REQUIRE(moved.is_unspecified());
	REQUIRE_FALSE(moved.is_multicast());
	REQUIRE_FALSE(moved.is_link_local());
	REQUIRE_FALSE(moved.is_site_local());
	REQUIRE_FALSE(moved.is_v4_mapped());
	REQUIRE_FALSE(moved.is_multicast_global());
	REQUIRE_FALSE(moved.is_multicast_link_local());
	REQUIRE_FALSE(moved.is_multicast_node_local());
	REQUIRE_FALSE(moved.is_multicast_org_local());
	REQUIRE_FALSE(moved.is_multicast_site_local());
}

TEST_CASE("Comparison operator", "[address_v6]")
{
	address_v6 addr;
	auto addr1 = address_v6::any();
	address_v6 addr3({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf, 5, 3});

	REQUIRE(addr == addr1);
	REQUIRE_FALSE(addr1 == addr3);
}

TEST_CASE("Rom string", "[address_v6]")
{
	auto addr = address_v6::from_str("::1");
	auto data = addr.to_bytes();

	REQUIRE(equal(loopback_array.begin(), loopback_array.end(), data.begin(), data.end()));
	REQUIRE(addr.to_string() == "::1");
	REQUIRE(addr.is_loopback());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE_FALSE(addr.is_unspecified());
	REQUIRE_FALSE(addr.is_multicast());
	REQUIRE_FALSE(addr.is_unspecified());
	REQUIRE_FALSE(addr.is_link_local());
	REQUIRE_FALSE(addr.is_site_local());
	REQUIRE_FALSE(addr.is_v4_mapped());
	REQUIRE_FALSE(addr.is_multicast_global());
	REQUIRE_FALSE(addr.is_multicast_link_local());
	REQUIRE_FALSE(addr.is_multicast_node_local());
	REQUIRE_FALSE(addr.is_multicast_org_local());
	REQUIRE_FALSE(addr.is_multicast_site_local());
}
