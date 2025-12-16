#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <postgresql/libpq-fe.h>
#include <time.h>
#include <iomanip>
#include <openssl/sha.h>
using namespace std;
#define PORT 8080
#define BUFFER_SIZE 4096

struct Database {
    PGconn *conn;
    
    Database() {
        const char* conninfo = "host=database dbname=infosec_db user=postgres password=postgres";
        conn = PQconnectdb(conninfo);
        if (PQstatus(conn) != CONNECTION_OK) {
            cerr << "Connection to database failed: " << PQerrorMessage(conn) << endl;
            PQfinish(conn);
            exit(1);
        }
    }
    
    ~Database() {
        PQfinish(conn);
    }
};

// Глобальное подключение к БД (в реальном приложении лучше использовать пул соединений)
Database db;

// Простая структура для сессий (в реальном приложении использовать Redis или БД)
map<string, int> sessions; // token -> user_id
pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

// Утилиты для работы с HTTP
string urlDecode(const string& str) {
    string result;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '+') {
            result += ' ';
        } else if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            istringstream is(str.substr(i + 1, 2));
            if (is >> hex >> value) {
                result += static_cast<char>(value);
                i += 2;
            } else {
                result += str[i];
            }
        } else {
            result += str[i];
        }
    }
    return result;
}

map<string, string> parseQueryString(const string& query) {
    map<string, string> params;
    istringstream ss(query);
    string pair;
    
    while (getline(ss, pair, '&')) {
        size_t pos = pair.find('=');
        if (pos != string::npos) {
            string key = urlDecode(pair.substr(0, pos));
            string value = urlDecode(pair.substr(pos + 1));
            params[key] = value;
        }
    }
    return params;
}

string generateToken() {
    srand(time(nullptr));
    string token;
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < 32; ++i) {
        token += charset[rand() % (sizeof(charset) - 1)];
    }
    return token;
}

string sha256(const string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.length());
    SHA256_Final(hash, &sha256);
    
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int getUserIdFromToken(const string& token) {
    pthread_mutex_lock(&sessions_mutex);
    auto it = sessions.find(token);
    int userId = (it != sessions.end()) ? it->second : -1;
    pthread_mutex_unlock(&sessions_mutex);
    return userId;
}

bool isAdmin(int userId) {
    if (userId == -1) return false;
    
    const char* query = "SELECT role_id FROM users WHERE id = $1";
    const char* paramValues[1];
    string userIdStr = to_string(userId);
    paramValues[0] = userIdStr.c_str();
    const int paramLengths[1] = {userIdStr.length()};
    const int paramFormats[1] = {0};
    
    PGresult* res = PQexecParams(db.conn, query, 1, nullptr, paramValues, paramLengths, paramFormats, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return false;
    }
    
    if (PQntuples(res) == 0) {
        PQclear(res);
        return false;
    }
    
    int roleId = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return roleId == 1; // 1 = admin
}

string jsonEscape(const string& str) {
    string result;
    for (char c : str) {
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else result += c;
    }
    return result;
}

string sendResponse(int clientSocket, const string& status, const string& contentType, const string& body, const map<string, string>& headers = {}) {
    stringstream response;
    response << status << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    response << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    
    for (const auto& header : headers) {
        response << header.first << ": " << header.second << "\r\n";
    }
    
    response << "\r\n" << body;
    
    string responseStr = response.str();
    send(clientSocket, responseStr.c_str(), responseStr.length(), 0);
    return responseStr;
}

void handleRequest(int clientSocket) {
    char buffer[BUFFER_SIZE] = {0};
    recv(clientSocket, buffer, BUFFER_SIZE, 0);
    
    string request(buffer);
    istringstream requestStream(request);
    string method, path, version;
    requestStream >> method >> path >> version;
    
    // CORS preflight
    if (method == "OPTIONS") {
        sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", "");
        close(clientSocket);
        return;
    }
    
    // Извлечение query string
    size_t queryPos = path.find('?');
    string pathOnly = (queryPos != string::npos) ? path.substr(0, queryPos) : path;
    // Удаление завершающего слеша
    if (pathOnly.length() > 1 && pathOnly.back() == '/') {
        pathOnly.pop_back();
    }
    string queryString = (queryPos != string::npos) ? path.substr(queryPos + 1) : "";
    auto queryParams = parseQueryString(queryString);
    
    // Извлечение токена из заголовков
    string authToken;
    size_t authPos = request.find("Authorization: ");
    if (authPos != string::npos) {
        size_t tokenStart = authPos + 15;
        size_t tokenEnd = request.find("\r\n", tokenStart);
        if (tokenEnd != string::npos) {
            authToken = request.substr(tokenStart, tokenEnd - tokenStart);
        }
    }
    
    // API endpoints
    if (pathOnly == "/api/sections") {
        const char* query = "SELECT id, name, description FROM sections ORDER BY id";
        PGresult* res = PQexec(db.conn, query);
        
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                        "{\"error\":\"Database error\"}");
            PQclear(res);
            close(clientSocket);
            return;
        }
        
        stringstream json;
        json << "[";
        int rows = PQntuples(res);
        for (int i = 0; i < rows; i++) {
            if (i > 0) json << ",";
            json << "{\"id\":" << PQgetvalue(res, i, 0) 
                 << ",\"name\":\"" << jsonEscape(PQgetvalue(res, i, 1))
                 << "\",\"description\":\"" << jsonEscape(PQgetvalue(res, i, 2)) << "\"}";
        }
        json << "]";
        
        sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", json.str());
        PQclear(res);
    }
    else if (pathOnly == "/api/content") {
        if (method == "GET") {
            int sectionId = queryParams.find("section_id") != queryParams.end() 
                ? stoi(queryParams["section_id"]) : 0;
            
            const char* query;
            PGresult* res;
            
            if (sectionId > 0) {
                // Защита от SQL инъекций: параметризованный запрос
                query = "SELECT id, section_id, title, content_text, created_at, updated_at FROM content WHERE section_id = $1 ORDER BY id";
                const char* paramValues[1];
                string sectionIdStr = to_string(sectionId);
                paramValues[0] = sectionIdStr.c_str();
                const int paramLengths[1] = {sectionIdStr.length()};
                const int paramFormats[1] = {0};
                res = PQexecParams(db.conn, query, 1, nullptr, paramValues, paramLengths, paramFormats, 0);
            } else {
                query = "SELECT id, section_id, title, content_text, created_at, updated_at FROM content ORDER BY id";
                res = PQexec(db.conn, query);
            }
            
            if (PQresultStatus(res) != PGRES_TUPLES_OK) {
                sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                            "{\"error\":\"Database error\"}");
                PQclear(res);
                close(clientSocket);
                return;
            }
            
            stringstream json;
            json << "[";
            int rows = PQntuples(res);
            for (int i = 0; i < rows; i++) {
                if (i > 0) json << ",";
                json << "{\"id\":" << PQgetvalue(res, i, 0)
                     << ",\"section_id\":" << PQgetvalue(res, i, 1)
                     << ",\"title\":\"" << jsonEscape(PQgetvalue(res, i, 2))
                     << "\",\"content_text\":\"" << jsonEscape(PQgetvalue(res, i, 3))
                     << "\",\"created_at\":\"" << jsonEscape(PQgetvalue(res, i, 4))
                     << "\",\"updated_at\":\"" << jsonEscape(PQgetvalue(res, i, 5)) << "\"}";
            }
            json << "]";
            
            sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", json.str());
            PQclear(res);
        }
        else if (method == "POST") {
            int userId = getUserIdFromToken(authToken);
            if (!isAdmin(userId)) {
                sendResponse(clientSocket, "HTTP/1.1 403 Forbidden", "application/json", 
                            "{\"error\":\"Admin access required\"}");
                close(clientSocket);
                return;
            }
            
            // Извлечение тела запроса
            size_t bodyPos = request.find("\r\n\r\n");
            string body = (bodyPos != string::npos) ? request.substr(bodyPos + 4) : "";
            auto bodyParams = parseQueryString(body);
            
            if (bodyParams.find("section_id") == bodyParams.end() || 
                bodyParams.find("title") == bodyParams.end() ||
                bodyParams.find("content_text") == bodyParams.end()) {
                sendResponse(clientSocket, "HTTP/1.1 400 Bad Request", "application/json", 
                            "{\"error\":\"Missing required fields\"}");
                close(clientSocket);
                return;
            }
            
            // Параметризованный запрос для защиты от SQL инъекций
            const char* query = "INSERT INTO content (section_id, title, content_text, author_id) VALUES ($1, $2, $3, $4) RETURNING id";
            const char* paramValues[4];
            paramValues[0] = bodyParams["section_id"].c_str();
            paramValues[1] = bodyParams["title"].c_str();
            paramValues[2] = bodyParams["content_text"].c_str();
            string userIdStr = to_string(userId);
            paramValues[3] = userIdStr.c_str();
            const int paramLengths[4] = {bodyParams["section_id"].length(), 
                                        bodyParams["title"].length(), 
                                        bodyParams["content_text"].length(), 
                                        userIdStr.length()};
            const int paramFormats[4] = {0, 0, 0, 0};
            
            PGresult* res = PQexecParams(db.conn, query, 4, nullptr, paramValues, paramLengths, paramFormats, 0);
            
            if (PQresultStatus(res) != PGRES_TUPLES_OK) {
                sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                            "{\"error\":\"Database error\"}");
                PQclear(res);
                close(clientSocket);
                return;
            }
            
            string newId = PQgetvalue(res, 0, 0);
            sendResponse(clientSocket, "HTTP/1.1 201 Created", "application/json", 
                        "{\"id\":" + newId + ",\"message\":\"Content created\"}");
            PQclear(res);
        }
    }
    else if (pathOnly.find("/api/content/") == 0 && pathOnly.length() > 13) {
        string idStr = pathOnly.substr(13);
        int contentId = stoi(idStr);
        
        if (method == "PUT") {
            int userId = getUserIdFromToken(authToken);
            if (!isAdmin(userId)) {
                sendResponse(clientSocket, "HTTP/1.1 403 Forbidden", "application/json", 
                            "{\"error\":\"Admin access required\"}");
                close(clientSocket);
                return;
            }
            
            size_t bodyPos = request.find("\r\n\r\n");
            string body = (bodyPos != string::npos) ? request.substr(bodyPos + 4) : "";
            auto bodyParams = parseQueryString(body);
            
            if (bodyParams.find("title") == bodyParams.end() || 
                bodyParams.find("content_text") == bodyParams.end()) {
                sendResponse(clientSocket, "HTTP/1.1 400 Bad Request", "application/json", 
                            "{\"error\":\"Missing required fields\"}");
                close(clientSocket);
                return;
            }
            
            // Параметризованный запрос
            const char* query = "UPDATE content SET title = $1, content_text = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3";
            const char* paramValues[3];
            paramValues[0] = bodyParams["title"].c_str();
            paramValues[1] = bodyParams["content_text"].c_str();
            string idStrParam = to_string(contentId);
            paramValues[2] = idStrParam.c_str();
            const int paramLengths[3] = {bodyParams["title"].length(), 
                                        bodyParams["content_text"].length(), 
                                        idStrParam.length()};
            const int paramFormats[3] = {0, 0, 0};
            
            PGresult* res = PQexecParams(db.conn, query, 3, nullptr, paramValues, paramLengths, paramFormats, 0);
            
            if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                            "{\"error\":\"Database error\"}");
                PQclear(res);
                close(clientSocket);
                return;
            }
            
            sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", 
                        "{\"message\":\"Content updated\"}");
            PQclear(res);
        }
        else if (method == "DELETE") {
            int userId = getUserIdFromToken(authToken);
            if (!isAdmin(userId)) {
                sendResponse(clientSocket, "HTTP/1.1 403 Forbidden", "application/json", 
                            "{\"error\":\"Admin access required\"}");
                close(clientSocket);
                return;
            }
            
            // Параметризованный запрос
            const char* query = "DELETE FROM content WHERE id = $1";
            const char* paramValues[1];
            string idStrParam = to_string(contentId);
            paramValues[0] = idStrParam.c_str();
            const int paramLengths[1] = {idStrParam.length()};
            const int paramFormats[1] = {0};
            
            PGresult* res = PQexecParams(db.conn, query, 1, nullptr, paramValues, paramLengths, paramFormats, 0);
            
            if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                            "{\"error\":\"Database error\"}");
                PQclear(res);
                close(clientSocket);
                return;
            }
            
            sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", 
                        "{\"message\":\"Content deleted\"}");
            PQclear(res);
        }
    }
    else if (pathOnly == "/api/register" && method == "POST") {
        size_t bodyPos = request.find("\r\n\r\n");
        string body = (bodyPos != string::npos) ? request.substr(bodyPos + 4) : "";
        auto bodyParams = parseQueryString(body);
        
        if (bodyParams.find("username") == bodyParams.end() || 
            bodyParams.find("email") == bodyParams.end() ||
            bodyParams.find("password") == bodyParams.end()) {
            sendResponse(clientSocket, "HTTP/1.1 400 Bad Request", "application/json", 
                        "{\"error\":\"Missing required fields\"}");
            close(clientSocket);
            return;
        }
        
        // Хеширование пароля
        string passwordHash = sha256(bodyParams["password"]);
        
        // Параметризованный запрос
        const char* query = "INSERT INTO users (username, email, password_hash, role_id) VALUES ($1, $2, $3, 2) RETURNING id";
        const char* paramValues[3];
        paramValues[0] = bodyParams["username"].c_str();
        paramValues[1] = bodyParams["email"].c_str();
        paramValues[2] = passwordHash.c_str();
        const int paramLengths[3] = {bodyParams["username"].length(), 
                                    bodyParams["email"].length(), 
                                    passwordHash.length()};
        const int paramFormats[3] = {0, 0, 0};
        
        PGresult* res = PQexecParams(db.conn, query, 3, nullptr, paramValues, paramLengths, paramFormats, 0);
        
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            string error = PQerrorMessage(db.conn);
            if (error.find("unique") != string::npos) {
                sendResponse(clientSocket, "HTTP/1.1 409 Conflict", "application/json", 
                            "{\"error\":\"Username or email already exists\"}");
            } else {
                sendResponse(clientSocket, "HTTP/1.1 500 Internal Server Error", "application/json", 
                            "{\"error\":\"Database error\"}");
            }
            PQclear(res);
            close(clientSocket);
            return;
        }
        
        string userId = PQgetvalue(res, 0, 0);
        sendResponse(clientSocket, "HTTP/1.1 201 Created", "application/json", 
                    "{\"id\":" + userId + ",\"message\":\"User created\"}");
        PQclear(res);
    }
    else if (pathOnly == "/api/login" && method == "POST") {
        size_t bodyPos = request.find("\r\n\r\n");
        string body = (bodyPos != string::npos) ? request.substr(bodyPos + 4) : "";
        auto bodyParams = parseQueryString(body);
        
        if (bodyParams.find("username") == bodyParams.end() || 
            bodyParams.find("password") == bodyParams.end()) {
            sendResponse(clientSocket, "HTTP/1.1 400 Bad Request", "application/json", 
                        "{\"error\":\"Missing username or password\"}");
            close(clientSocket);
            return;
        }
        
        string passwordHash = sha256(bodyParams["password"]);
        
        // Параметризованный запрос
        const char* query = "SELECT id, role_id FROM users WHERE username = $1 AND password_hash = $2";
        const char* paramValues[2];
        paramValues[0] = bodyParams["username"].c_str();
        paramValues[1] = passwordHash.c_str();
        const int paramLengths[2] = {bodyParams["username"].length(), passwordHash.length()};
        const int paramFormats[2] = {0, 0};
        
        PGresult* res = PQexecParams(db.conn, query, 2, nullptr, paramValues, paramLengths, paramFormats, 0);
        
        if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
            sendResponse(clientSocket, "HTTP/1.1 401 Unauthorized", "application/json", 
                        "{\"error\":\"Invalid credentials\"}");
            PQclear(res);
            close(clientSocket);
            return;
        }
        
        int userId = atoi(PQgetvalue(res, 0, 0));
        int roleId = atoi(PQgetvalue(res, 0, 1));
        string token = generateToken();
        
        pthread_mutex_lock(&sessions_mutex);
        sessions[token] = userId;
        pthread_mutex_unlock(&sessions_mutex);
        
        stringstream json;
        json << "{\"token\":\"" << token << "\",\"user_id\":" << userId << ",\"role_id\":" << roleId << "}";
        sendResponse(clientSocket, "HTTP/1.1 200 OK", "application/json", json.str());
        PQclear(res);
    }
    else {
        sendResponse(clientSocket, "HTTP/1.1 404 Not Found", "application/json", 
                    "{\"error\":\"Not found\"}");
    }
    
    close(clientSocket);
}

void* clientHandler(void* arg) {
    int clientSocket = *(int*)arg;
    delete (int*)arg;
    handleRequest(clientSocket);
    return nullptr;
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == 0) {
        cerr << "Socket creation failed" << endl;
        return 1;
    }
    
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        cerr << "Bind failed" << endl;
        return 1;
    }
    
    if (listen(serverSocket, 10) < 0) {
        cerr << "Listen failed" << endl;
        return 1;
    }
    
    cout << "Server started on port " << PORT << endl;
    
    while (true) {
        socklen_t addrlen = sizeof(address);
        int* clientSocket = new int;
        *clientSocket = accept(serverSocket, (struct sockaddr *)&address, &addrlen);
        
        if (*clientSocket < 0) {
            delete clientSocket;
            continue;
        }
        
        pthread_t thread;
        pthread_create(&thread, nullptr, clientHandler, clientSocket);
        pthread_detach(thread);
    }
    
    close(serverSocket);
    return 0;
}

