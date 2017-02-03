#include <array>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <mstd/range.hpp>

#include "pe-res.hpp"

namespace PE {

namespace {

mstd::range<unsigned char const> read_data(mstd::range<unsigned char const> & data, size_t n_bytes, int error) {
	if (data.size() < n_bytes) throw error;
	auto d = data.subrange(0, n_bytes);
	data.remove_prefix(n_bytes);
	return d;
}

uint32_t read_uint32(mstd::range<unsigned char const> & data, int error) {
	auto buf = read_data(data, 4, error);
	return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
};

uint32_t read_uint16(mstd::range<unsigned char const> & data, int error) {
	auto buf = read_data(data, 2, error);
	return buf[0] | buf[1] << 8;
};

void write_uint16(unsigned char * data, uint16_t value) {
	data[0] = value      & 0xFF;
	data[1] = value >> 8 & 0xFF;
}

void write_uint32(unsigned char * data, uint32_t value) {
	data[0] = value       & 0xFF;
	data[1] = value >>  8 & 0xFF;
	data[2] = value >> 16 & 0xFF;
	data[3] = value >> 24 & 0xFF;
}

std::u16string resource_name(uint32_t name, mstd::range<unsigned char const> section) {
	if (name & 0x80000000) {
		uint32_t offset = name & 0x7FFFFFFF;
		auto data = section.subrange(offset);
		size_t length = read_uint16(data, 100);
		std::u16string s;
		s.reserve(length);
		for (size_t i = 0; i < length; ++i) {
			s.push_back(read_uint16(data, 101));
		}
		return s;
	} else {
		return from_number(name);
	}
}

void parse_resources_(
	mstd::range<unsigned char const> resource_section,
	uint32_t section_virtual_address,
	int level,
	mstd::range<unsigned char const> data,
	ResourceId & id,
	std::map<ResourceId, mstd::range<unsigned char const>> & resources
) {
	data.remove_prefix(12); // Skip unused fields.

	uint16_t n_named_entries = read_uint16(data, 1);
	uint16_t n_id_entries    = read_uint16(data, 2);

	size_t n_entries = n_named_entries + n_id_entries;

	for (size_t i = 0; i < n_entries; ++i) {
		uint32_t name   = read_uint32(data, 3);
		uint32_t offset = read_uint32(data, 4);

		id[level] = resource_name(name, resource_section);

		if (offset < 0x80000000) {
			if (level != 2) throw 11;

			auto r = resource_section.subrange(offset, 16);
			uint32_t data_vaddr = read_uint32(r, 5);
			uint32_t data_size  = read_uint32(r, 6);
			read_uint32(r, 7); // code_page
			read_uint32(r, 8); // resource_handle

			auto data = resource_section.subrange(data_vaddr - section_virtual_address, data_size);
			if (data.size() != data_size) throw 9;
			resources.emplace(id, data);

		} else {
			if (level >= 2) throw 10;
			offset &= 0x7FFFFFFF;
			parse_resources_(resource_section, section_virtual_address, level + 1, resource_section.subrange(offset), id, resources);
		}
	}
}

}

std::map<ResourceId, mstd::range<unsigned char const>> parse_resources(
	mstd::range<unsigned char const> resource_section,
	uint32_t section_virtual_address
) try {
	std::map<ResourceId, mstd::range<unsigned char const>> resources;

	ResourceId resource_id;
	parse_resources_(resource_section, section_virtual_address, 0, resource_section, resource_id, resources);

	return resources;
} catch (int error) {
	throw std::runtime_error("Unable to parse resource section. (Error " + std::to_string(error) + ")");
}

bool is_numeric(std::u16string const & s) {
	if (s.empty()) return false;
	for (char16_t c : s) if (c < u'0' || c > u'9') return false;
	return true;
}

std::u16string from_number(uint32_t value) {
	char buf[11];
	size_t n = snprintf(buf, sizeof(buf), "%d", value);
	std::u16string s;
	s.reserve(n);
	for (size_t i = 0; i < n; ++i) {
		s.push_back(buf[i]);
	}
	return s;
}

uint32_t to_number(std::u16string const & s) {
	uint32_t value = 0;
	for (char16_t c : s) {
		if (c < u'0' || c > u'9') return 0;
		value *= 10;
		value += c - u'0';
	}
	return value;
}

namespace {

void align(std::vector<unsigned char> & data, unsigned int alignment) {
	data.resize((data.size() + alignment - 1) & ~(alignment - 1));
}

struct NameBlock {
	std::u16string const * name;
	size_t parent_pointer_offset;
};

struct ResBlock {
	mstd::range<unsigned char const> data;
	size_t parent_pointer_offset;
};

void serialize_resources_1(
	std::map<ResourceId, mstd::range<unsigned char const>>::const_iterator begin,
	std::map<ResourceId, mstd::range<unsigned char const>>::const_iterator end,
	int level,
	std::vector<unsigned char> & data,
	std::vector<NameBlock> & name_blocks,
	std::vector<ResBlock> & res_blocks
) {
	size_t n_named_entries = 0;
	size_t n_id_entries = 0;

	for (auto i = begin, last = end; i != end; last = i++) {
		std::u16string const & n = i->first[level];
		if (last == end || last->first[level] != n) {
			++(is_numeric(n) ? n_id_entries : n_named_entries);
		}
	}

	size_t n_entries = n_named_entries + n_id_entries;

	size_t start_offset = data.size();

	data.resize(data.size() + 16 + n_entries * 8);

	write_uint16(data.data() + start_offset + 12, n_named_entries);
	write_uint16(data.data() + start_offset + 14, n_id_entries);

	size_t entries_offset = start_offset + 16;

	auto i = begin;
	while (i != end) {
		std::u16string const & n = i->first[level];
		if (is_numeric(n)) {
			write_uint32(data.data() + entries_offset, to_number(n));
		} else {
			NameBlock b;
			b.parent_pointer_offset = entries_offset;
			b.name = &n;
			name_blocks.push_back(std::move(b));
		}
		auto b = i;
		while (++i != end && i->first[level] == n);
		if (level < 2) {
			write_uint32(data.data() + entries_offset + 4, data.size() | 0x80000000);
			serialize_resources_1(b, i, level + 1, data, name_blocks, res_blocks);
		} else {
			assert(std::next(b) == i);
			ResBlock r;
			r.parent_pointer_offset = entries_offset + 4;
			r.data = b->second;
			res_blocks.push_back(std::move(r));
		}
		entries_offset += 8;
	}
}

void serialize_resources_2(
	std::vector<unsigned char> & data,
	uint32_t section_virtual_address,
	std::vector<NameBlock> const & name_blocks,
	std::vector<ResBlock> const & res_blocks
) {
	align(data, 2);
	for (auto const & b : name_blocks) {
		size_t offset = data.size();
		data.push_back(b.name->size()      & 0xFF);
		data.push_back(b.name->size() >> 8 & 0xFF);
		for (char c : *b.name) {
			data.push_back(c);
			data.push_back(0);
		}
		write_uint32(data.data() + b.parent_pointer_offset, offset | 0x80000000);
	}
	align(data, 8);
	size_t res_offset = data.size();
	data.resize(data.size() + res_blocks.size() * 16);
	for (auto const & b : res_blocks) {
		write_uint32(data.data() + b.parent_pointer_offset, res_offset);
		write_uint32(data.data() + res_offset, data.size() + section_virtual_address);
		write_uint32(data.data() + res_offset + 4, b.data.size());
		res_offset += 16;
		data.insert(data.end(), b.data.begin(), b.data.end());
		align(data, 8);
	}
}

int compare_resname(std::u16string const & a, std::u16string const & b) {
	bool a_num = is_numeric(a);
	bool b_num = is_numeric(b);
	if (a_num != b_num) return a_num ? 1 : -1;
	if (a_num) {
		long a_val = to_number(a);
		long b_val = to_number(b);
		return a_val < b_val ? -1 : a_val > b_val ? 1 : 0;
	} else {
		return a < b ? -1 : a > b ? 1 : 0;
	}
}

}

bool operator < (ResourceId const & a, ResourceId const & b) {
	if (auto x = compare_resname(a.type, b.type)) return x < 0;
	if (auto x = compare_resname(a.name, b.name)) return x < 0;
	if (auto x = compare_resname(a.lang, b.lang)) return x < 0;
	return false;
}

std::vector<unsigned char> serialize_resources(
	std::map<ResourceId, mstd::range<unsigned char const>> const & resources,
	uint32_t section_virtual_address
) {
	std::vector<unsigned char> section;
	std::vector<NameBlock> name_blocks;
	std::vector<ResBlock> res_blocks;

	// Serialize the structure, and populate {name,res}_blocks.
	serialize_resources_1(resources.begin(), resources.end(), 0, section, name_blocks, res_blocks);

	// Serialize {name,res}_blocks, and fill in the pointers/offsets to these blocks.
	serialize_resources_2(section, section_virtual_address, name_blocks, res_blocks);

	return section;
}

namespace {

struct VerInfoNode {
	std::u16string name;

	mstd::range<unsigned char const> data;

	bool is_string = false;
	std::u16string string_value; // Only set when is_string.

	std::vector<VerInfoNode> children;
};

unsigned char const * x = nullptr;
VerInfoNode parse_ver_info_node(mstd::range<unsigned char const> & data) {
	VerInfoNode node;

	if (!x) x = data.data();

	size_t size = read_uint16(data, 101);

	auto d = data.subrange(0, size - 2);
	if (d.size() != size - 2) throw 102;

	while (size % 4 != 0) ++size;
	data.remove_prefix(std::min(data.size(), size - 2));

	size_t val_len = read_uint16(d, 103);
	uint16_t type = read_uint16(d, 104);

	while (char16_t c = read_uint16(d, 105)) {
		node.name.push_back(c);
	}

	if (node.name.size() % 2 != 0) d.remove_prefix(2); // Alignment.

	if (type == 0) {
		node.is_string = false;
		node.data = d.subrange(0, val_len);
		d.remove_prefix(val_len);
		if (val_len % 4) d.remove_prefix(std::min(d.size(), 4 - (val_len % 4)));
	} else if (type == 1) {
		node.is_string = true;
		node.data = d.subrange(0, val_len * 2);
		if (val_len > 0) {
			node.string_value.reserve(val_len - 1);
			for (size_t i = 0; i < val_len - 1; ++i) {
				node.string_value.push_back(read_uint16(d, 107));
			}
			if (read_uint16(d, 108) != 0) throw 109; // Terminating null.
			if (val_len % 2) d.remove_prefix(std::min<size_t>(d.size(), 2));
		}
	} else {
		throw 106;
	}

	while (!d.empty()) {
		node.children.push_back(parse_ver_info_node(d));
	}

	return node;
}

void serialize_ver_info_node(std::vector<unsigned char> & data, VerInfoNode const & node) {
	size_t s = data.size();
	data.resize(data.size() + 6);
	size_t val_byte_len = node.is_string && !node.string_value.empty() ? node.string_value.size() * 2 + 2 : node.data.size();
	data.reserve(data.size() + (node.name.size() + 1) * 2 + val_byte_len);
	write_uint16(&data[s + 2], node.is_string ? val_byte_len / 2 : val_byte_len);
	write_uint16(&data[s + 4], node.is_string);
	for (char16_t c : node.name) {
		data.push_back(c & 0xFF);
		data.push_back(c >> 8);
	}
	data.push_back(0);
	data.push_back(0);
	align(data, 4);
	if (node.is_string && !node.string_value.empty()) {
		for (char16_t c : node.string_value) {
			data.push_back(c & 0xFF);
			data.push_back(c >> 8);
		}
		data.push_back(0);
		data.push_back(0);
	} else {
		data.insert(data.end(), node.data.begin(), node.data.end());
	}
	align(data, 4);
	for (auto const & c : node.children) {
		serialize_ver_info_node(data, c);
	}
	align(data, 4);
	write_uint16(&data[s], data.size() - s);
}

}

VersionInfo parse_version_info(mstd::range<unsigned char const> data) try {
	VersionInfo info = {};

	auto root = parse_ver_info_node(data);

	if (root.name != u"VS_VERSION_INFO") throw 1;
	if (root.is_string) throw 2;

	info.signature        = read_uint32(root.data, 3);
	info.struc_version    = read_uint32(root.data, 4);
	info.file_version     = read_uint32(root.data, 5);
	info.file_version    |= uint64_t(read_uint32(root.data, 6)) << 32;
	info.product_version  = read_uint32(root.data, 7);
	info.product_version |= uint64_t(read_uint32(root.data, 8)) << 32;
	info.file_flags_mask  = read_uint32(root.data, 9);
	info.file_flags       = read_uint32(root.data, 10);
	info.file_os          = read_uint32(root.data, 11);
	info.file_type        = read_uint32(root.data, 12);
	info.file_subtype     = read_uint32(root.data, 13);
	info.file_date        = read_uint32(root.data, 14);
	info.file_date       |= uint64_t(read_uint32(root.data, 15)) << 32;

	if (root.data.size() > 2) throw 16;

	if (info.signature != 0xFEEF04BD) throw 17;

	for (auto const & c : root.children) {
		if (c.name == u"StringFileInfo") {
			if (info.string_file_info) throw 18;
			if (!c.data.empty()) throw 19;
			info.string_file_info = std::make_unique<StringFileInfo>();
			for (auto const & b : c.children) {
				std::vector<std::pair<std::u16string, std::u16string>> values;
				for (auto const & v : b.children) {
					if (!v.is_string || !v.children.empty()) throw 20;
					values.emplace_back(std::move(v.name), std::move(v.string_value));
				}
				info.string_file_info->blocks.emplace_back(
					std::move(b.name), std::move(values)
				);
			}
		} else if (c.name == u"VarFileInfo") {
			if (info.var_file_info) throw 21;
			if (!c.data.empty()) throw 22;
			info.var_file_info = std::make_unique<VarFileInfo>();
			for (auto const & v : c.children) {
				if (v.is_string || !v.children.empty()) throw 23;
				info.var_file_info->values.emplace_back(
					std::move(v.name),
					std::vector<unsigned char>(v.data.begin(), v.data.end())
				);
			}
		} else {
			throw 24;
		}
	}

	return info;

} catch (int error) {
	throw std::runtime_error("Unable to parse version information. (Error " + std::to_string(error) + ")");
}

std::vector<unsigned char> serialize_version_info(VersionInfo const & info) {

	unsigned char fixed_version_info[0x34];
	write_uint32(fixed_version_info + 0x00, info.signature);
	write_uint32(fixed_version_info + 0x04, info.struc_version);
	write_uint32(fixed_version_info + 0x08, info.file_version);
	write_uint32(fixed_version_info + 0x0c, info.file_version >> 32);
	write_uint32(fixed_version_info + 0x10, info.product_version);
	write_uint32(fixed_version_info + 0x14, info.product_version >> 32);
	write_uint32(fixed_version_info + 0x18, info.file_flags_mask);
	write_uint32(fixed_version_info + 0x1c, info.file_flags);
	write_uint32(fixed_version_info + 0x20, info.file_os);
	write_uint32(fixed_version_info + 0x24, info.file_type);
	write_uint32(fixed_version_info + 0x28, info.file_subtype);
	write_uint32(fixed_version_info + 0x2c, info.file_date);
	write_uint32(fixed_version_info + 0x30, 0);

	VerInfoNode root;
	root.name = u"VS_VERSION_INFO";
	root.data = fixed_version_info;

	if (info.string_file_info) {
		root.children.emplace_back();
		auto & strfileinfo = root.children.back();
		strfileinfo.name = u"StringFileInfo";
		strfileinfo.is_string = true;
		for (auto const & b : info.string_file_info->blocks) {
			strfileinfo.children.emplace_back();
			auto & block = strfileinfo.children.back();
			block.name = b.first;
			block.is_string = true;
			for (auto const & v : b.second) {
				block.children.emplace_back();
				auto & value = block.children.back();
				value.name = v.first;
				value.is_string = true;
				value.string_value = v.second;
			}
		}
	}

	if (info.var_file_info) {
		root.children.emplace_back();
		auto & varfileinfo = root.children.back();
		varfileinfo.name = u"VarFileInfo";
		for (auto const & v : info.var_file_info->values) {
			varfileinfo.children.emplace_back();
			auto & value = varfileinfo.children.back();
			value.name = v.first;
			value.data = v.second;
		}
	}

	std::vector<unsigned char> data;
	serialize_ver_info_node(data, root);
	return data;
}

}
