#ifndef NETWORK_ADDRESS_V6_HPP
#define NETWORK_ADDRESS_V6_HPP

#include "../error.hpp"
#include "../native.hpp"

#include <array>
#include <ostream>
#include <string>

namespace network::ip
{
	class address_v6
	{
	  public:
		using scope_type = uint32_t;
		using bytes_type = std::array<uint8_t, 16>;

		static int address_family() { return native::v6; }

		static address_v6 any() noexcept { return {}; }

		static address_v6 loopback() noexcept { return address_v6{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}; }

		static address_v6 from_str(std::string_view str)
		{
			address_v6 address;

			int out = inet_pton(AF_INET6, str.data(), &address);
			if(out <= 0)
				throw error::address(native::error_code(), __FUNCTION__);
			return address;
		}

		address_v6() noexcept = default;

		explicit address_v6(const bytes_type& bytes) { std::copy(bytes.cbegin(), bytes.cend(), data.begin()); }
		explicit address_v6(in_addr* address) : data(*(reinterpret_cast<bytes_type*>(address))) {}

		[[nodiscard]] scope_type scope_id() const noexcept { return scope_id_; }

		void scope_id(scope_type id) noexcept { scope_id_ = id; }

		[[nodiscard]] bytes_type to_bytes() const noexcept { return data; }

		[[nodiscard]] std::string to_string() const
		{
			char buf[64];

			auto out = ::inet_ntop(AF_INET6, reinterpret_cast<const void*>(this), buf, static_cast<socklen_t>(64));
			if(out == nullptr)
				throw error::address(native::error_code(), __FUNCTION__);
			return std::string(out);
		}

		[[nodiscard]] bool is_loopback() const noexcept { return native::is_address_loopback(data.data()); }

		[[nodiscard]] bool is_unspecified() const noexcept { return native::is_address_unspecified(data.data()); }

		[[nodiscard]] bool is_link_local() const noexcept { return native::is_address_link_local(data.data()); }

		[[nodiscard]] bool is_site_local() const noexcept { return native::is_address_site_local(data.data()); }

		[[nodiscard]] bool is_v4_mapped() const noexcept { return native::is_address_v4_mapped(data.data()); }

		[[nodiscard]] bool is_multicast() const noexcept { return native::is_address_multi_cast(data.data()); }

		[[nodiscard]] bool is_multicast_global() const noexcept { return native::is_address_mc_global(data.data()); }

		[[nodiscard]] bool is_multicast_link_local() const noexcept { return native::is_address_mc_local(data.data()); }

		[[nodiscard]] bool is_multicast_node_local() const noexcept { return native::is_address_mc_node_local(data.data()); }

		[[nodiscard]] bool is_multicast_org_local() const noexcept { return native::is_address_mc_org_local(data.data()); }

		[[nodiscard]] bool is_multicast_site_local() const noexcept { return native::is_address_mc_site_local(data.data()); }

	  private:
		bytes_type data{};
		scope_type scope_id_{};
	};

	bool operator==(const address_v6& a1, const address_v6& a2) noexcept
	{
		return native::is_address_equal(reinterpret_cast<const unsigned char*>(&a1), reinterpret_cast<const unsigned char*>(&a2));
	}

	bool operator!=(const address_v6& a1, const address_v6& a2) noexcept { return !(a1 == a2); }

	template<typename Elem, typename Traits>
	std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& os, const address_v6& address)
	{
		os << address.to_string();
		return os;
	}
} // namespace network::ip

#endif // NETWORK_ADDRESS_V6_HPP
