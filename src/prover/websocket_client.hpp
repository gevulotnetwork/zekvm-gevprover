#pragma once

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>

typedef websocketpp::client<websocketpp::config::asio_client> client;

class WebSocketClient {
public:
    WebSocketClient();
    void connect(const std::string &uri);
    std::string send_and_receive(const std::string &message);

private:
    void on_open(websocketpp::connection_hdl hdl);
    void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg);
    void on_close(websocketpp::connection_hdl hdl);

    client m_client;
    websocketpp::connection_hdl m_hdl;
    std::atomic<bool> m_open;
    std::atomic<bool> m_done;
    std::string m_response;
};
