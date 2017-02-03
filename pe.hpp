#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace PE {

struct Section {
	std::string name;
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t characteristics;
	std::vector<unsigned char> data;
};

struct PortableExecutable {
	std::vector<unsigned char> headers;
	std::vector<Section> sections;
};

PortableExecutable read_pe_file(FILE *);

void write_pe_file(FILE *, PortableExecutable const &);

PortableExecutable read_pe_file(char const * file_name);
void write_pe_file(char const * file_name, PortableExecutable const &);
#ifdef WIN32
PortableExecutable read_pe_file(wchar_t const * file_name);
void write_pe_file(wchar_t const * file_name, PortableExecutable const &);
#endif

}
