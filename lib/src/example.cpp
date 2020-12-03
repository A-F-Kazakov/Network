#include <Template/example.hpp>

using std::string;
using std::ostream;

example::example() = default;

example::example(const string& dta) : data(dta){}

ostream& operator<<(ostream &os, const example& ex)
{
	os << ex.data;
	return os;
}	
