#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <string>
#include <condition_variable>
#include <mutex>

typedef websocketpp::client<websocketpp::config::asio_client> client;

class WebSocketClient
{
public:
    WebSocketClient() : m_open(false), m_done(false)
    {
        m_client.init_asio();
        m_client.set_open_handler(bind(&WebSocketClient::on_open, this, ::_1));
        m_client.set_message_handler(bind(&WebSocketClient::on_message, this, ::_1, ::_2));
        m_client.set_close_handler(bind(&WebSocketClient::on_close, this, ::_1));
    }

    void on_open(websocketpp::connection_hdl hdl)
    {
        m_hdl = hdl;
        m_open = true;
        m_cond.notify_all();
        std::cout << "Connection opened" << std::endl;
    }

    void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_response = msg->get_payload();
            m_done = true;
        }
        m_cond.notify_all();
        std::cout << "Received message: " << m_response << std::endl;
    }

    void on_close(websocketpp::connection_hdl hdl)
    {
        std::cout << "Connection closed" << std::endl;
    }

    void run(const std::string &uri)
    {
        websocketpp::lib::error_code ec;
        client::connection_ptr con = m_client.get_connection(uri, ec);
        if (ec)
        {
            std::cout << "Could not create connection because: " << ec.message() << std::endl;
            return;
        }

        m_client.connect(con);
        std::thread([this]()
                    { m_client.run(); })
            .detach();
    }

    std::string send_and_receive(const std::string &message)
    {
        // Wait for the connection to open
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this]
                    { return m_open; });

        m_client.send(m_hdl, message, websocketpp::frame::opcode::text);

        // Wait for the response
        m_cond.wait(lock, [this]
                    { return m_done; });

        return m_response;
    }

private:
    client m_client;
    websocketpp::connection_hdl m_hdl;
    std::string m_response;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    bool m_open;
    bool m_done;
};
