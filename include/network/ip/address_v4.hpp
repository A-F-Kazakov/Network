#ifndef NETWORK_ADDRESS_V4_HPP
#define NETWORK_ADDRESS_V4_HPP

#include "../error.hpp"
#include "../native.hpp"

#include <array>
#include <ostream>
#include <string>

namespace network::ip
{
	struct address_v4
	{
		using uint_type  = uint32_t;
		using bytes_type = std::array<uint8_t, 4>;

		static int address_family() { return native::v4; }

		static address_v4 any() noexcept { return {}; }

		static address_v4 loopback() noexcept { return address_v4(0x7f000001); }

		static address_v4 broadcast() noexcept { return address_v4(0xffffffff); }

		static address_v4 from_str(std::string_view str)
		{
			address_v4 address;

			int out = ::inet_pton(native::v4, str.data(), &address);
			if(out <= 0)
				throw error::address(native::error_code(), __FUNCTION__);
			return address;
		}

		address_v4() noexcept = default;

		explicit address_v4(uint_type address) noexcept : union_data(native::to_network_format(address)) {}
		explicit address_v4(const bytes_type& bytes) : union_data(native::to_network_format(*((uint_type*)&bytes))) {}
		explicit address_v4(in_addr* addr) : union_data(*((uint_type*)addr)) {}

		[[nodiscard]] bytes_type to_bytes() const noexcept { return union_data.bytes; }

		[[nodiscard]] uint_type to_uint() const noexcept { return native::from_network_format(union_data.data); }

		[[nodiscard]] std::string to_string() const
		{
			char buf[64];

			auto out = ::inet_ntop(native::v4, reinterpret_cast<const void*>(this), buf, static_cast<socklen_t>(64));
			if(out == nullptr)
				throw error::address(native::error_code(), __FUNCTION__);
			return std::string(out);
		}

		[[nodiscard]] bool is_loopback() const noexcept
		{
			return (union_data.data == network::native::to_network_format((uint32_t)0x7f000001));
		}

		[[nodiscard]] bool is_unspecified() const noexcept { return !(is_loopback() || is_multicast()); }

		[[nodiscard]] bool is_multicast() const noexcept
		{
			return (union_data.data == 0xe0000000) || (union_data.data == 0xe0000001) || (union_data.data == 0xe0000002) ||
					 (union_data.data == 0xe00000ff);
		}

	  private:
		native::sock_addr_v4 data{};
	};

	bool operator==(const address_v4& a1, const address_v4& a2) noexcept { return a1.to_uint() == a2.to_uint(); }

	bool operator!=(const address_v4& a1, const address_v4& a2) noexcept { return !(a1 == a2); }

	template<typename Elem, typename Traits>
	std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& os, const address_v4& address)
	{
		os << address.to_string();
		return os;
	}
} // namespace network::ip

#endif // NETWORK_ADDRESS_V4_HPP
