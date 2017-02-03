#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "pe.hpp"

namespace PE {

namespace {

void read_data(FILE * f, unsigned char * buf, size_t n_bytes, int error) {
	int s = fread(buf, n_bytes, 1, f);
	if (s < 0) throw std::runtime_error("Unable to read from file.");
	if (s != 1) throw error;
}

uint32_t read_uint32(FILE * f, int error) {
	unsigned char buf[4];
	read_data(f, buf, 4, error);
	return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
};

uint16_t read_uint16(FILE * f, int error) {
	unsigned char buf[2];
	read_data(f, buf, 2, error);
	return buf[0] | buf[1] << 8;
};

void write_data(FILE * f, unsigned char const * buf, size_t n_bytes) {
	if (fwrite(buf, n_bytes, 1, f) != 1) throw std::runtime_error("Unable to write to file.");
}

void write_uint16(FILE * f, uint16_t value) {
	unsigned char buf[2];
	buf[0] = value      & 0xFF;
	buf[1] = value >> 8 & 0xFF;
	write_data(f, buf, 2);
}

void write_uint32(FILE * f, uint32_t value) {
	unsigned char buf[4];
	buf[0] = value       & 0xFF;
	buf[1] = value >>  8 & 0xFF;
	buf[2] = value >> 16 & 0xFF;
	buf[3] = value >> 24 & 0xFF;
	write_data(f, buf, 4);
}

size_t padding(size_t address, size_t align) {
	size_t new_address = (address + align - 1) & ~(align - 1);
	return new_address - address;
}

}

PortableExecutable read_pe_file(FILE * f) try {
	PortableExecutable pe;

	if (read_uint16(f, 1) != 0x5a4d) throw 2;
	if (fseek(f, 0x3C, SEEK_SET) != 0) throw 3;
	uint32_t pe_header_offset = read_uint32(f, 4);
	if (fseek(f, pe_header_offset, SEEK_SET) != 0) throw 5;
	if (read_uint32(f, 6) != 0x00004550) throw 7;
	if (fseek(f, 2, SEEK_CUR) != 0) throw 8;
	uint16_t n_sections = read_uint16(f, 9);
	if (fseek(f, 12, SEEK_CUR) != 0) throw 10;
	uint16_t optheader_size = read_uint16(f, 11);
	if (fseek(f, 2 + optheader_size, SEEK_CUR) != 0) throw 12;

	int header_end = ftell(f);
	if (header_end < 0) throw 27;
	fseek(f, 0, SEEK_SET);

	pe.headers.resize(header_end);
	read_data(f, pe.headers.data(), pe.headers.size(), 28);

	pe.sections.resize(n_sections);

	for (auto & section : pe.sections) {
		char section_name[9] = {};
		if (fread(section_name, 8, 1, f) != 1) throw 13;
		section.name = section_name;

		section.virtual_size    = read_uint32(f, 14);
		section.virtual_address = read_uint32(f, 15);

		uint32_t data_size   = read_uint32(f, 16);
		uint32_t data_offset = read_uint32(f, 17);

		if (read_uint32(f, 18) != 0) throw 29; // reloc_offset
		if (read_uint32(f, 19) != 0) throw 30; // lineno_offset
		if (read_uint16(f, 20) != 0) throw 31; // n_reloc
		if (read_uint16(f, 21) != 0) throw 32; // n_lineno

		section.characteristics = read_uint32(f, 22);

		int o = ftell(f);
		if (o < 0) throw 23;

		if (fseek(f, data_offset, SEEK_SET) != 0) throw 24;
		section.data.resize(data_size);
		if (section.data.size() > 0) {
			read_data(f, section.data.data(), section.data.size(), 25);
		}

		if (fseek(f, o, SEEK_SET) != 0) throw 26;
	}

	return pe;
} catch (int error) {
	throw std::runtime_error("Unable to parse PE file. (Error " + std::to_string(error) + ")");
}

void write_pe_file(FILE * f, PortableExecutable const & pe) {
	// TODO: correct image/file size headers
	write_data(f, pe.headers.data(), pe.headers.size());

	size_t section_table_size = 40 * pe.sections.size();

	size_t first_section_data_offset = pe.headers.size() + section_table_size;
	size_t section_data_offset = first_section_data_offset;

	for (auto & section : pe.sections) {
		unsigned char section_name[8] = {};
		section.name.copy((char *)section_name, 8);
		write_data(f, section_name, 8);
		write_uint32(f, section.virtual_size);
		write_uint32(f, section.virtual_address);
		size_t data_padding = padding(section.data.size(), 512);
		write_uint32(f, section.data.size() + data_padding);
		if (section.data.empty()) {
			write_uint32(f, 0);
		} else {
			section_data_offset += padding(section_data_offset, 512);
			write_uint32(f, section_data_offset);
			section_data_offset += section.data.size() + data_padding;
		}
		write_uint32(f, 0); // reloc_offset
		write_uint32(f, 0); // lineno_offset
		write_uint16(f, 0); // n_reloc
		write_uint16(f, 0); // n_lineno
		write_uint32(f, section.characteristics);
	}

	section_data_offset = first_section_data_offset;

	for (auto & section : pe.sections) {
		size_t p = padding(section_data_offset, 512);
		section_data_offset += p;
		if (p) write_data(f, std::vector<unsigned char>(p).data(), p);
		if (!section.data.empty()) write_data(f, section.data.data(), section.data.size());
		p = padding(section.data.size(), 512);
		if (p) write_data(f, std::vector<unsigned char>(p).data(), p);
		section_data_offset += section.data.size() + p;
	}
}

PortableExecutable read_pe_file(char const * file_name) {
	FILE * f = fopen(file_name, "rb");
	if (!f) throw std::runtime_error("Unable to open file.");
	PortableExecutable pe;
	try {
		pe = read_pe_file(f);
	} catch (...) {
		fclose(f);
		throw;
	}
	fclose(f);
	return pe;
}

#ifdef WIN32
PortableExecutable read_pe_file(wchar_t const * file_name) {
	FILE * f = _wfopen(file_name, L"rb");
	if (!f) throw std::runtime_error("Unable to open file.");
	PortableExecutable pe;
	try {
		pe = read_pe_file(f);
	} catch (...) {
		fclose(f);
		throw;
	}
	fclose(f);
	return pe;
}
#endif

void write_pe_file(char const * file_name, PortableExecutable const & pe) {
	FILE * f = fopen(file_name, "wb");
	if (!f) throw std::runtime_error("Unable to open file.");
	try {
		write_pe_file(f, pe);
	} catch (...) {
		fclose(f);
		throw;
	}
	fclose(f);
}

#ifdef WIN32
void write_pe_file(wchar_t const * file_name, PortableExecutable const & pe) {
	FILE * f = _wfopen(file_name, L"wb");
	if (!f) throw std::runtime_error("Unable to open file.");
	try {
		write_pe_file(f, pe);
	} catch (...) {
		fclose(f);
		throw;
	}
	fclose(f);
}
#endif

}
