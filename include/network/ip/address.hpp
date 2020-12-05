#ifndef NETWORK_ADDRESS_HPP
#define NETWORK_ADDRESS_HPP

#include "address_v4.hpp"
#include "address_v6.hpp"
#include "../basic_resolver_results.hpp"

namespace network::ip
{
	template<typename Version>
	class basic_resolver_results;

	class address
	{
	  public:
		using v4 = address_v4;
		using v6 = address_v6;

		template<typename Version>
		static Version from_str(std::string_view str)
		{
			return Version::from_str(str);
		}

		template<typename Version>
		static basic_resolver_results<Version> resolve(std::string_view str)
		{
			struct hostent* hp = native::resolve_host(str.data(), Version::address_family());

			if(hp == nullptr)
				throw error::address(native::error_code(), __FUNCTION__);

			return basic_resolver_results<Version>{hp};
		}

		constexpr explicit address(const v4& other) noexcept : type_(ipv4), ipv4_address_(other) {}
		constexpr explicit address(const v6& other) noexcept : type_(ipv6), ipv6_address_(other) {}

		constexpr address& operator=(const v4& ipv4_address) noexcept
		{
			type_			  = ipv4;
			ipv4_address_ = ipv4_address;
			return *this;
		}

		constexpr address& operator=(const v6& ipv6_address) noexcept
		{
			type_			  = ipv6;
			ipv6_address_ = ipv6_address;
			return *this;
		}

		[[nodiscard]] constexpr bool is_v4() const noexcept { return (type_ == ipv4); }

		[[nodiscard]] constexpr bool is_v6() const noexcept { return (type_ == ipv6); }

		[[nodiscard]] v4 to_v4() const
		{
			if(is_v6())
				throw std::bad_cast();
			return ipv4_address_;
		}

		[[nodiscard]] v6 to_v6() const
		{
			if(is_v4())
				throw std::bad_cast();
			return ipv6_address_;
		}

		[[nodiscard]] std::string to_string() const
		{
			if(type_ == ipv4)
				return ipv4_address_.to_string();
			else
				return ipv6_address_.to_string();
		}

		[[nodiscard]] bool is_loopback() const noexcept
		{
			if(type_ == ipv4)
				return ipv4_address_.is_loopback();
			else
				return ipv6_address_.is_loopback();
		}

		[[nodiscard]] bool is_unspecified() const noexcept
		{
			if(type_ == ipv4)
				return ipv4_address_.is_unspecified();
			else
				return ipv6_address_.is_unspecified();
		}

		[[nodiscard]] bool is_multicast() const noexcept
		{
			if(type_ == ipv4)
				return ipv4_address_.is_multicast();
			else
				return ipv6_address_.is_multicast();
		}

	  private:
		enum { ipv4, ipv6 } type_;

		union
		{
			v4 ipv4_address_;
			v6 ipv6_address_{};
		};
	};

	bool operator==(const address& a1, const address& a2) noexcept
	{
		if((a1.is_v4() && a2.is_v4()))
			return (a1.to_v4() == a2.to_v4());
		else if(a1.is_v6() && a2.is_v6())
			return (a1.to_v6() == a2.to_v6());
		else
			return false;
	}

	bool operator!=(const address& a1, const address& a2) noexcept { return !(a1 == a2); }

	template<typename Elem, typename Traits>
	std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& os, const address& addr)
	{
		os << addr.to_string();
		return os;
	}
} // namespace network::ip

#endif // NETWORK_ADDRESS_HPP
