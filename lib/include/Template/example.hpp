#ifndef EXAMPLE_HPP
#define EXAMPLE_HPP

#include <string>
#include <ostream>

struct example
{
	example();
	example(const std::string&);

	friend std::ostream& operator<<(std::ostream&, const example&);

	private:
	std::string data;
};

#endif //EXAMPLE_HPP
