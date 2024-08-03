#include "websocket_client.hpp"

WebSocketClient::WebSocketClient() : m_open(false), m_done(false) {
    m_client.init_asio();

    m_client.set_open_handler(bind(&WebSocketClient::on_open, this, std::placeholders::_1));
    m_client.set_message_handler(bind(&WebSocketClient::on_message, this, std::placeholders::_1, std::placeholders::_2));
    m_client.set_close_handler(bind(&WebSocketClient::on_close, this, std::placeholders::_1));
}

void WebSocketClient::connect(const std::string &uri) {
    websocketpp::lib::error_code ec;
    client::connection_ptr con = m_client.get_connection(uri, ec);

    if (ec) {
        std::cout << "Could not create connection because: " << ec.message() << std::endl;
        return;
    }

    m_client.connect(con);
    std::thread t([this]() { m_client.run(); });

    while (!m_open) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    t.detach();
}

std::string WebSocketClient::send_and_receive(const std::string &message) {
    if (m_open) {
        m_client.send(m_hdl, message, websocketpp::frame::opcode::text);
    } else {
        std::cout << "Connection is not open." << std::endl;
    }

    while (!m_done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return m_response;
}

void WebSocketClient::on_open(websocketpp::connection_hdl hdl) {
    std::cout << "Connection opened." << std::endl;
    m_hdl = hdl;
    m_open = true;
}

void WebSocketClient::on_message(websocketpp::connection_hdl hdl, client::message_ptr msg) {
    m_response = msg->get_payload();
    m_done = true;
}

void WebSocketClient::on_close(websocketpp::connection_hdl hdl) {
    std::cout << "Connection closed." << std::endl;
    m_open = false;
}
