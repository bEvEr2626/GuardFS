#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

struct FileEntry {
	std::string path;
	bool recursive;
	bool auto_update;
};

struct RuntimeOptions {
	std::chrono::seconds interval{1};
	std::string targets_file{"fileguard.targets"};
	std::string hash_db_file{"fileguard.hashes"};
	std::string log_file{"fileguard.log"};
	bool once{false};
};

struct FileFingerprint {
	uintmax_t size;
	std::int64_t mtime_ticks;
};

class HashEngine {
public:
	static std::string calculateSHA256(std::string_view path) {
		std::ifstream file(std::string(path), std::ios::binary);
		if (!file) {
			return {};
		}

		EVP_MD_CTX* raw_ctx = EVP_MD_CTX_new();
		if (raw_ctx == nullptr) {
			return {};
		}

		std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw_ctx, &EVP_MD_CTX_free);

		if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
			return {};
		}

		std::vector<unsigned char> buffer(8192);
		while (file) {
			file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
			const std::streamsize bytes_read = file.gcount();
			if (bytes_read > 0 && EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytes_read)) != 1) {
				return {};
			}
		}

		unsigned char digest[EVP_MAX_MD_SIZE]{};
		unsigned int digest_len = 0;
		if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1) {
			return {};
		}

		std::string hex;
		hex.reserve(digest_len * 2);
		for (unsigned int i = 0; i < digest_len; ++i) {
			hex += std::format("{:02x}", digest[i]);
		}
		return hex;
	}
};

class Logger {
public:
	explicit Logger(std::string log_path)
		: log_stream_(std::move(log_path), std::ios::app) {}

	void info(const std::string& message) {
		writeLine(std::format("[{}] INFO {}", timestampNow(), message));
	}

	void warn(const std::string& message) {
		writeLine(std::format("[{}] WARN {}", timestampNow(), message));
	}

	void fileModified(const std::string& path, const std::string& old_hash, const std::string& new_hash) {
		writeLine(std::format(
			"[{}] FILE_MODIFIED path={} old={} new={}",
			timestampNow(),
			path,
			old_hash,
			new_hash));
	}

private:
	std::ofstream log_stream_;
	std::mutex mutex_;

	static std::string timestampNow() {
		const auto now = std::chrono::system_clock::now();
		const std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
		std::tm local_tm{};
		localtime_r(&now_time_t, &local_tm);
		char buffer[20]{};
		std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_tm);
		return buffer;
	}

	void writeLine(const std::string& line) {
		std::scoped_lock lock(mutex_);
		if (!log_stream_) {
			return;
		}
		log_stream_ << line << '\n';
		log_stream_.flush();
	}
};

namespace {
std::atomic_bool g_should_stop{false};

void signalHandler(int) {
	g_should_stop.store(true);
}

std::string trim(const std::string& value) {
	const auto start = value.find_first_not_of(" \t\r\n");
	if (start == std::string::npos) {
		return {};
	}
	const auto end = value.find_last_not_of(" \t\r\n");
	return value.substr(start, end - start + 1);
}

bool parseBool(std::string value, bool& out) {
	value = trim(value);
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});

	if (value == "1" || value == "true" || value == "yes" || value == "on") {
		out = true;
		return true;
	}
	if (value == "0" || value == "false" || value == "no" || value == "off") {
		out = false;
		return true;
	}
	return false;
}

bool parsePositiveInt(const std::string& text, int& value) {
	try {
		size_t consumed = 0;
		const int parsed = std::stoi(text, &consumed);
		if (consumed != text.size() || parsed <= 0) {
			return false;
		}
		value = parsed;
		return true;
	} catch (...) {
		return false;
	}
}

std::string expandUserPath(const std::string& input) {
	if (input.empty() || input[0] != '~') {
		return input;
	}
	const char* home = std::getenv("HOME");
	if (home == nullptr) {
		return input;
	}
	if (input.size() == 1) {
		return std::string(home);
	}
	if (input[1] == '/') {
		return std::string(home) + input.substr(1);
	}
	return input;
}

std::string normalizePath(const fs::path& input) {
	std::error_code ec;
	fs::path canonical = fs::weakly_canonical(input, ec);
	if (!ec) {
		return canonical.string();
	}

	ec.clear();
	fs::path absolute = fs::absolute(input, ec);
	if (!ec) {
		return absolute.lexically_normal().string();
	}
	return input.lexically_normal().string();
}

bool loadTargets(const std::string& file_path, std::vector<FileEntry>& entries, std::string& error) {
	entries.clear();

	std::ifstream input(file_path);
	if (!input) {
		error = std::format("Cannot open targets file: {}", file_path);
		return false;
	}

	std::string line;
	int line_number = 0;
	while (std::getline(input, line)) {
		++line_number;
		std::string text = trim(line);
		if (text.empty() || text[0] == '#') {
			continue;
		}

		std::string path_part;
		std::string recursive_part;
		std::string auto_part;

		size_t first = text.find('|');
		if (first == std::string::npos) {
			path_part = trim(text);
			recursive_part = "0";
			auto_part = "0";
		} else {
			size_t second = text.find('|', first + 1);
			if (second == std::string::npos) {
				error = std::format("Invalid targets format at line {}", line_number);
				return false;
			}
			path_part = trim(text.substr(0, first));
			recursive_part = trim(text.substr(first + 1, second - first - 1));
			auto_part = trim(text.substr(second + 1));
		}

		bool recursive = false;
		bool auto_update = false;
		if (path_part.empty() || !parseBool(recursive_part, recursive) || !parseBool(auto_part, auto_update)) {
			error = std::format("Invalid targets values at line {}", line_number);
			return false;
		}

		entries.push_back(FileEntry{expandUserPath(path_part), recursive, auto_update});
	}

	return true;
}

bool loadHashes(const std::string& hash_db_file, std::unordered_map<std::string, std::string>& hashes) {
	hashes.clear();
	std::ifstream input(hash_db_file);
	if (!input) {
		return true;
	}

	std::string line;
	while (std::getline(input, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}

		const size_t sep = line.find('\t');
		if (sep == std::string::npos || sep == 0 || sep + 1 >= line.size()) {
			continue;
		}

		std::string path = line.substr(0, sep);
		std::string hash = line.substr(sep + 1);
		hashes[std::move(path)] = std::move(hash);
	}
	return true;
}

bool saveHashes(const std::string& hash_db_file, const std::unordered_map<std::string, std::string>& hashes) {
	const std::string tmp_file = hash_db_file + ".tmp";
	{
		std::ofstream output(tmp_file, std::ios::trunc);
		if (!output) {
			return false;
		}

		for (const auto& [path, hash] : hashes) {
			output << path << '\t' << hash << '\n';
		}
	}

	std::error_code ec;
	fs::rename(tmp_file, hash_db_file, ec);
	if (ec) {
		fs::remove(hash_db_file, ec);
		ec.clear();
		fs::rename(tmp_file, hash_db_file, ec);
		if (ec) {
			return false;
		}
	}
	return true;
}

void printUsage(const std::string& app_name) {
	std::cout
		<< "Usage:\n"
		<< "  " << app_name << " [--interval SECONDS] [--targets FILE] [--hash-db FILE] [--log FILE] [--once]\n\n"
		<< "Targets file format (user-editable):\n"
		<< "  path|recursive|auto_update\n"
		<< "Examples:\n"
		<< "  ~/.bashrc|0|1\n"
		<< "  ~/.config|1|1\n"
		<< "  /etc|1|0\n";
}

bool parseArguments(int argc, char** argv, RuntimeOptions& options) {
	for (int i = 1; i < argc; ++i) {
		const std::string arg = argv[i];

		auto nextValue = [&](std::string& out) {
			if (i + 1 >= argc) {
				return false;
			}
			out = argv[++i];
			return true;
		};

		if (arg == "--help" || arg == "-h") {
			printUsage(argv[0]);
			std::exit(0);
		}

		if (arg == "--interval") {
			std::string value;
			if (!nextValue(value)) {
				return false;
			}
			int seconds = 0;
			if (!parsePositiveInt(value, seconds)) {
				return false;
			}
			options.interval = std::chrono::seconds(seconds);
			continue;
		}

		if (arg == "--targets") {
			if (!nextValue(options.targets_file)) {
				return false;
			}
			continue;
		}

		if (arg == "--hash-db") {
			if (!nextValue(options.hash_db_file)) {
				return false;
			}
			continue;
		}

		if (arg == "--log") {
			if (!nextValue(options.log_file)) {
				return false;
			}
			continue;
		}

		if (arg == "--once") {
			options.once = true;
			continue;
		}

		return false;
	}

	options.targets_file = expandUserPath(options.targets_file);
	options.hash_db_file = expandUserPath(options.hash_db_file);
	options.log_file = expandUserPath(options.log_file);
	return true;
}
}  // namespace

class Scanner {
public:
	Scanner(RuntimeOptions options, Logger& logger)
		: options_(std::move(options)), logger_(logger) {
		ignored_exact_paths_.insert(stripTrailingSeparators(normalizePath(fs::path(options_.targets_file))));
		ignored_exact_paths_.insert(stripTrailingSeparators(normalizePath(fs::path(options_.hash_db_file))));
		ignored_exact_paths_.insert(stripTrailingSeparators(normalizePath(fs::path(options_.log_file))));
		loadHashes(options_.hash_db_file, file_hashes_);
	}

	void runOnce() {
		scanOnce();
	}

	void start() {
		worker_ = std::jthread([this](std::stop_token stop_token) {
			while (!stop_token.stop_requested()) {
				scanOnce();
				sleepInterruptible(stop_token, options_.interval);
			}
		});
	}

	void stop() {
		if (worker_.joinable()) {
			worker_.request_stop();
			worker_.join();
		}
	}

private:
	RuntimeOptions options_;
	Logger& logger_;
	std::unordered_map<std::string, std::string> file_hashes_;
	std::unordered_map<std::string, FileFingerprint> file_fingerprints_;
	std::unordered_set<std::string> ignored_exact_paths_;
	std::jthread worker_;

	static std::string stripTrailingSeparators(std::string value) {
		while (value.size() > 1) {
			const char last = value.back();
			if (last != '/' && last != '\\') {
				break;
			}
			value.pop_back();
		}
		return value;
	}

	static bool readFingerprint(const std::string& path, FileFingerprint& fingerprint) {
		std::error_code ec;
		const fs::path file_path(path);

		const uintmax_t size = fs::file_size(file_path, ec);
		if (ec) {
			return false;
		}

		ec.clear();
		const auto mtime = fs::last_write_time(file_path, ec);
		if (ec) {
			return false;
		}

		fingerprint = FileFingerprint{size, static_cast<std::int64_t>(mtime.time_since_epoch().count())};
		return true;
	}

	static void sleepInterruptible(std::stop_token stop_token, std::chrono::seconds duration) {
		const auto until = std::chrono::steady_clock::now() + duration;
		while (!stop_token.stop_requested() && std::chrono::steady_clock::now() < until) {
			std::this_thread::sleep_for(200ms);
		}
	}

	void scanOnce() {
		std::vector<FileEntry> entries;
		std::string load_error;
		if (!loadTargets(options_.targets_file, entries, load_error)) {
			logger_.warn(load_error);
			return;
		}

		std::unordered_map<std::string, bool> targets;
		collectTargetFiles(entries, targets);
		for (auto it = targets.begin(); it != targets.end();) {
			if (isIgnoredRuntimePath(it->first)) {
				it = targets.erase(it);
			} else {
				++it;
			}
		}
		if (targets.empty()) {
			logger_.warn("No readable files found in targets list");
			return;
		}

		bool hashes_changed = pruneStaleState(targets);

		std::vector<std::string> paths;
		paths.reserve(targets.size());
		for (const auto& [path, _] : targets) {
			paths.push_back(path);
		}

		std::vector<std::string> paths_to_hash;
		paths_to_hash.reserve(paths.size());
		for (const auto& path : paths) {
			FileFingerprint fingerprint{};
			if (!readFingerprint(path, fingerprint)) {
				continue;
			}

			auto hash_it = file_hashes_.find(path);
			auto fp_it = file_fingerprints_.find(path);
			if (hash_it != file_hashes_.end() && fp_it != file_fingerprints_.end()
				&& fp_it->second.size == fingerprint.size
				&& fp_it->second.mtime_ticks == fingerprint.mtime_ticks) {
				continue;
			}

			file_fingerprints_[path] = fingerprint;
			paths_to_hash.push_back(path);
		}

		if (paths_to_hash.empty()) {
			if (hashes_changed && !saveHashes(options_.hash_db_file, file_hashes_)) {
				logger_.warn(std::format("Failed to save hash DB file: {}", options_.hash_db_file));
			}
			return;
		}

		const unsigned hw = std::thread::hardware_concurrency();
		const size_t worker_count = std::max<size_t>(1, std::min<size_t>(hw == 0 ? 4 : hw, paths_to_hash.size()));

		std::atomic_size_t index{0};
		std::vector<std::pair<std::string, std::string>> hashed_results;
		hashed_results.reserve(paths_to_hash.size());
		std::mutex results_mutex;

		{
			std::vector<std::jthread> workers;
			workers.reserve(worker_count);

			for (size_t i = 0; i < worker_count; ++i) {
				workers.emplace_back([&](std::stop_token stop_token) {
					while (!stop_token.stop_requested()) {
						const size_t current = index.fetch_add(1);
						if (current >= paths_to_hash.size()) {
							break;
						}

						const std::string& path = paths_to_hash[current];
						const std::string hash = HashEngine::calculateSHA256(path);
						if (hash.empty()) {
							continue;
						}

						std::scoped_lock lock(results_mutex);
						hashed_results.emplace_back(path, hash);
					}
				});
			}
		}

		for (const auto& [path, new_hash] : hashed_results) {
			auto existing = file_hashes_.find(path);
			if (existing == file_hashes_.end()) {
				file_hashes_[path] = new_hash;
				hashes_changed = true;
				continue;
			}

			if (existing->second != new_hash) {
				if (!isIgnoredRuntimePath(path)) {
					logger_.fileModified(path, existing->second, new_hash);
				}
				if (targets[path]) {
					existing->second = new_hash;
					hashes_changed = true;
				}
			}
		}

		if (hashes_changed && !saveHashes(options_.hash_db_file, file_hashes_)) {
			logger_.warn(std::format("Failed to save hash DB file: {}", options_.hash_db_file));
		}
	}

	bool pruneStaleState(const std::unordered_map<std::string, bool>& targets) {
		bool changed = false;

		for (auto it = file_hashes_.begin(); it != file_hashes_.end();) {
			if (!targets.contains(it->first)) {
				it = file_hashes_.erase(it);
				changed = true;
				continue;
			}
			++it;
		}

		for (auto it = file_fingerprints_.begin(); it != file_fingerprints_.end();) {
			if (!targets.contains(it->first)) {
				it = file_fingerprints_.erase(it);
				continue;
			}
			++it;
		}

		return changed;
	}

	static void collectTargetFiles(const std::vector<FileEntry>& entries, std::unordered_map<std::string, bool>& targets) {
		for (const auto& entry : entries) {
			const fs::path input(entry.path);
			std::error_code ec;

			if (!fs::exists(input, ec) || ec) {
				continue;
			}

			if (fs::is_regular_file(input, ec) && !ec) {
				markTarget(targets, input, entry.auto_update);
				continue;
			}

			if (!fs::is_directory(input, ec) || ec) {
				continue;
			}

			if (entry.recursive) {
				fs::recursive_directory_iterator iter(input, fs::directory_options::skip_permission_denied, ec);
				fs::recursive_directory_iterator end;
				if (ec) {
					continue;
				}

				while (iter != end) {
					std::error_code item_ec;
					if (iter->is_regular_file(item_ec) && !item_ec) {
						markTarget(targets, iter->path(), entry.auto_update);
					}

					item_ec.clear();
					iter.increment(item_ec);
					if (item_ec) {
						item_ec.clear();
					}
				}
				continue;
			}

			fs::directory_iterator iter(input, fs::directory_options::skip_permission_denied, ec);
			fs::directory_iterator end;
			if (ec) {
				continue;
			}

			while (iter != end) {
				std::error_code item_ec;
				if (iter->is_regular_file(item_ec) && !item_ec) {
					markTarget(targets, iter->path(), entry.auto_update);
				}

				item_ec.clear();
				iter.increment(item_ec);
				if (item_ec) {
					item_ec.clear();
				}
			}
		}
	}

	static void markTarget(std::unordered_map<std::string, bool>& targets, const fs::path& path, bool auto_update) {
		const std::string key = normalizePath(path);
		if (isIgnoredPath(key)) {
			return;
		}

		auto [it, inserted] = targets.emplace(key, auto_update);
		if (!inserted && auto_update) {
			it->second = true;
		}
	}

	static bool isIgnoredPath(const std::string& normalized_path) {
		const std::string normalized = stripTrailingSeparators(normalized_path);
		std::string lowered = normalized;
		std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
			return static_cast<char>(std::tolower(c));
		});

		if (lowered.find("/.sonarlint") != std::string::npos || lowered.find("\\.sonarlint") != std::string::npos
			|| lowered.find("sonarsource.sonarlint-vscode") != std::string::npos) {
			return true;
		}

		for (const auto& prefix : ignoredPathPrefixes()) {
			if (normalized == prefix) {
				return true;
			}
			if (normalized.size() > prefix.size() && normalized.rfind(prefix, 0) == 0
				&& (normalized[prefix.size()] == '/' || normalized[prefix.size()] == '\\')) {
				return true;
			}
		}
		return false;
	}

	bool isIgnoredRuntimePath(const std::string& normalized_path) const {
		const std::string normalized = stripTrailingSeparators(normalized_path);
		if (isIgnoredPath(normalized)) {
			return true;
		}

		if (ignored_exact_paths_.contains(normalized)) {
			return true;
		}

		std::string lowered = normalized;
		std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
			return static_cast<char>(std::tolower(c));
		});

		static const std::vector<std::string> noisy_segments = {
			"/.config/code/logs/",
			"/.config/code/cache/",
			"/.config/code/user/workspacestorage/",
			"/.local/share/sddm/",
			"/.local/share/telegramdesktop/",
			"/telemetry/",
			"/cache/",
			"/tmp/"
		};

		for (const auto& segment : noisy_segments) {
			if (lowered.find(segment) != std::string::npos) {
				return true;
			}
		}

		return false;
	}

	static const std::vector<std::string>& ignoredPathPrefixes() {
		static const std::vector<std::string> prefixes = [] {
			std::vector<std::string> result;
			result.push_back(stripTrailingSeparators(normalizePath(fs::path(expandUserPath("~/.sonarlint")))));
			return result;
		}();
		return prefixes;
	}
};

int main(int argc, char** argv) {
	std::cout << "FileGuard started (C++23)\n";

	RuntimeOptions options;
	if (!parseArguments(argc, argv, options)) {
		printUsage(argv[0]);
		return 1;
	}

	std::signal(SIGINT, signalHandler);
	std::signal(SIGTERM, signalHandler);

	Logger logger(options.log_file);
	logger.info(std::format(
		"Daemon initialized interval={}s targets={} hash_db={} log={}",
		options.interval.count(),
		options.targets_file,
		options.hash_db_file,
		options.log_file));

	Scanner scanner(options, logger);

	if (options.once) {
		scanner.runOnce();
		std::cout << "FileGuard finished one scan\n";
		return 0;
	}

	scanner.start();
	while (!g_should_stop.load()) {
		std::this_thread::sleep_for(250ms);
	}

	scanner.stop();
	logger.info("Daemon stopped");
	std::cout << "FileGuard stopped\n";
	return 0;
}
