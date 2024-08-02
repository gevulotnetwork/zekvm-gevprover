#ifndef WEBSOCKET_CLIENT_HPP
#define WEBSOCKET_CLIENT_HPP

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <string>
#include <mutex>
#include <condition_variable>

typedef websocketpp::client<websocketpp::config::asio_client> client;

class WebSocketClient
{
public:
    WebSocketClient();
    void run(const std::string &uri);
    std::string send_and_receive(const std::string &message);

private:
    void on_open(websocketpp::connection_hdl hdl);
    void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg);
    void on_close(websocketpp::connection_hdl hdl);

    client m_client;
    websocketpp::connection_hdl m_hdl;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    std::string m_response;
    bool m_open;
    bool m_done;
};

#endif // WEBSOCKET_CLIENT_HPP
