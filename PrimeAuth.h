#ifndef PRIMEAUTH_H_
#define PRIMEAUTH_H_

#include <atomic>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace PrimeAuth {

// ============================================================
// DATA STRUCTURES
// ============================================================

struct subscription_data {
    std::string subscription;
    std::string expiry;
    std::string timeleft;
};

struct user_data {
    std::string username;
    std::string ip;
    std::string hwid;
    std::string createdate;
    std::string lastlogin;
    std::vector<subscription_data> subscriptions;

    void clear() noexcept {
        username.clear();
        ip.clear();
        hwid.clear();
        createdate.clear();
        lastlogin.clear();
        subscriptions.clear();
    }
};

// ============================================================
// CLIENT CLASS
// ============================================================

class Client {
public:
    // Constructor
    Client(
        std::string api_url,
        std::string app_name,
        std::string owner_id,
        std::string app_secret,
        std::string version
    );
    ~Client();

    // ===== AUTHENTICATION =====
    bool Init();
    bool Login(const std::string& username, const std::string& password);
    bool Register(const std::string& username, const std::string& password, const std::string& license_key);
    bool License(const std::string& license_key);
    bool Upgrade(const std::string& username, const std::string& license_key);
    
    // ===== VARIABLES =====
    std::string Var(const std::string& variable_name);
    std::string GetVar(const std::string& variable_name);
    bool SetVar(const std::string& variable_name, const std::string& value);
    
    // ===== USER DATA =====
    const user_data& current_user() const noexcept;
    bool has_subscription(const std::string& subscription_name) const;

    // ===== STATUS =====
    const std::string& hwid() const noexcept;
    const std::string& session_id() const noexcept;
    const std::string& last_message() const noexcept;
    const std::string& last_raw_response() const noexcept;
    bool last_success() const noexcept;
    unsigned long last_http_status() const noexcept;

private:
    // ===== PRIVATE METHODS =====
    bool AuthCall(
        const std::string& type,
        const std::map<std::string, std::string>& params,
        bool expect_user_info = false
    );
    bool Call(
        const std::string& type,
        const std::map<std::string, std::string>& params,
        std::string& response,
        unsigned long& status_code
    );
    
    // Heartbeat
    void StartHeartbeat();
    void StopHeartbeat() noexcept;
    void HeartbeatLoop() noexcept;
    bool HeartbeatShouldTerminate(std::string& fatal_message) const;
    
    // Authentication Guard
    void ArmAuthenticationGuard() noexcept;
    void MarkAuthenticated() noexcept;
    void ResetAuthenticationGuard() noexcept;
    bool AuthenticationGraceExpired() const noexcept;
    bool AuthenticationGuardActive() const noexcept;
    
    // Data
    void ClearUserData() noexcept;
    void UpdateUserDataFromLastResponse();

    // ===== PRIVATE MEMBERS =====
    std::string api_url_;
    std::string app_name_;
    std::string owner_id_;
    std::string app_secret_;
    std::string version_;
    std::string enc_key_;
    std::string hwid_;
    std::string legacy_hwid_;
    std::string legacy_hwid_alt_;
    std::string session_id_;
    std::string last_message_;
    std::string last_raw_response_;
    bool last_success_ = false;
    unsigned long last_http_status_ = 0;
    user_data user_data_;
    
    std::atomic<bool> heartbeat_stop_{false};
    std::thread heartbeat_thread_;
    std::atomic<bool> authenticated_{false};
    std::atomic<unsigned long long> auth_deadline_tick_{0};
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

std::string GetHwid();
std::string GetHwid(const std::string& owner_id);
const std::string& ApiUrl() noexcept;

}  // namespace PrimeAuth

#endif  // PRIMEAUTH_H_