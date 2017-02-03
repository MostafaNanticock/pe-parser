#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <mstd/range.hpp>

namespace PE {

struct ResourceId {
	std::u16string type;
	std::u16string name;
	std::u16string lang;
	ResourceId() {}
	ResourceId(std::u16string type, std::u16string name, std::u16string lang)
		: type(std::move(type)), name(std::move(name)), lang(std::move(lang)) {}
	friend bool operator < (ResourceId const &, ResourceId const &);
	std::u16string & operator[] (size_t i) {
		return i == 0 ? type : i == 1 ? name : lang;
	}
	std::u16string const & operator[] (size_t i) const {
		return i == 0 ? type : i == 1 ? name : lang;
	}
};

bool is_numeric(std::u16string const &);
std::u16string from_number(uint32_t);
uint32_t to_number(std::u16string const &);

std::map<ResourceId, mstd::range<unsigned char const>> parse_resources(
	mstd::range<unsigned char const> resource_section,
	uint32_t section_virtual_address
);

std::vector<unsigned char> serialize_resources(
	std::map<ResourceId, mstd::range<unsigned char const>> const & resources,
	uint32_t section_virtual_address
);

struct StringFileInfo {
	std::vector<std::pair<
		std::u16string, // Block name (e.g. "000004b0")
		std::vector<std::pair<
			std::u16string, // Value name (e.g. "FileDescription")
			std::u16string  // Value (e.g. "Foo Bar Baz 2.0")
		>>
	>> blocks;
};

struct VarFileInfo {
	std::vector<std::pair<
		std::u16string,
		std::vector<unsigned char>
	>> values;
};

struct VersionInfo {
	uint32_t signature;
	uint32_t struc_version;
	uint64_t file_version;
	uint64_t product_version;
	uint32_t file_flags_mask;
	uint32_t file_flags;
	uint32_t file_os;
	uint32_t file_type;
	uint32_t file_subtype;
	uint64_t file_date;
	std::unique_ptr<VarFileInfo> var_file_info;
	std::unique_ptr<StringFileInfo> string_file_info;
};

VersionInfo parse_version_info(mstd::range<unsigned char const>);

std::vector<unsigned char> serialize_version_info(VersionInfo const &);

}
