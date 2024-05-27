#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <cstring>
#include <regex>

boost::asio::io_context io_context;

using boost::asio::ip::tcp;

#define BUF_SIZE 1024

class socks4a_match
{
public:
    explicit socks4a_match() {}

    template <typename Iterator>
    std::pair<Iterator, bool> operator()(
        Iterator begin, Iterator end) const
    {
        std::vector<char> header(begin, end);
        if (header.size() < 8)
            return std::make_pair(begin, false);

        int target_count = 1;
        if (!memcmp(&header[4], "\0\0\0", 3) && header[7])
            target_count = 2;

        int count = 0;
        Iterator i = begin + 8;
        while (i != end)
        {
            if ('\0' == *i++)
                ++count;
            if (count == target_count)
                return std::make_pair(i, true);
        }

        return std::make_pair(begin, false);
    }
};

namespace boost
{
    namespace asio
    {
        template <>
        struct is_match_condition<socks4a_match>
            : public boost::true_type
        {
        };
    }
};

class session : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket)
        : client(std::move(socket)), remote(io_context)
    {
    }

    void start()
    {
        auto self(shared_from_this());
        boost::asio::async_read_until(client, boost::asio::dynamic_buffer(header), socks4a_match(), [this, self](boost::system::error_code ec, std::size_t n)
                                      {
                if(ec)
                    return;
                parse_header(); });
    }
    void parse_header()
    {
        try
        {
            VN = header[0];
            if (VN != 4)
                return;

            CD = header[1];
            if (CD != 1 && CD != 2)
                return;

            int count = 0;
            int first = 0;
            for (std::size_t i = 8; i < header.size(); ++i)
            {
                if (!header[i])
                    ++count;
                if (count == 1)
                {
                    first = i + 1;
                    break;
                }
            }

            auto self(shared_from_this());
            if (CD == 1)
            {
                DSTPORT = std::to_string(header[2] << 8 | header[3]);
                if (!memcmp(&header[4], "\0\0\0", 3) && header[7])
                {
                    tcp::resolver resovler(io_context);
                    auto endpoints = resovler.resolve(std::string((char *)&header[first]), DSTPORT);
                    boost::asio::connect(remote, endpoints);
                    DSTIP = endpoints.begin()->endpoint().address().to_string();
                }
                else
                {
                    DSTIP = std::to_string((uint32_t)header[4]) + ".";
                    DSTIP += std::to_string((uint32_t)header[5]) + ".";
                    DSTIP += std::to_string((uint32_t)header[6]) + ".";
                    DSTIP += std::to_string((uint32_t)header[7]);
                    tcp::resolver resovler(io_context);
                    auto endpoints = resovler.resolve(DSTIP, DSTPORT);
                    boost::asio::connect(remote, endpoints);
                }

                memset(response, 0, 8);
                response[1] = 90;

                boost::asio::async_write(client, boost::asio::buffer(response, 8), [this, self](boost::system::error_code ec, std::size_t n)
                                         {
                    if(ec)
                        return;
                    pipe2remote();
                    pipe2client(); });
            }
            else
            {
                auto acceptor = new tcp::acceptor(io_context, tcp::endpoint(tcp::v4(), 0));

                memset(response, 0, 8);
                response[1] = 90;
                auto port = acceptor->local_endpoint().port();
                memcpy(response + 2, &port, 2);
                std::swap(response[2], response[3]);
                boost::asio::async_write(client, boost::asio::buffer(response, 8),
                                         [this, self, acceptor](boost::system::error_code ec, std::size_t n)
                                         {
                    if(ec)
                        return;
                    acceptor->async_accept(remote,
                        [this, self, acceptor](boost::system::error_code ec)
                        {
                            if(ec)
                                return;
                            pipe2remote();
                            pipe2client();
                            delete acceptor;
                        }); 
                     });
            }

            std::cout << "<S_IP>: " << client.remote_endpoint().address() << "\n";
            std::cout << "<S_PORT>: " << client.remote_endpoint().port() << "\n";
            std::cout << "<D_IP>: " << DSTIP << "\n";
            std::cout << "<D_PORT>: " << DSTPORT << "\n";
            std::cout << "<Command>: " << (CD == 1 ? "CONNECTION" : "BIND") << "\n";
            std::cout << "<Reply>: Accept\n\n";
        }
        catch (std::exception &e)
        {
            std::cerr << "Exception: " << e.what() << "\n";
            return;
        }
    }

    void pipe2remote()
    {
        auto self(shared_from_this());
        client.async_read_some(boost::asio::buffer(to_remote), [this, self](boost::system::error_code ec, std::size_t n)
                               {
			if (ec)
                return;
            boost::asio::async_write(remote, boost::asio::buffer(to_remote, n), [this, self](boost::system::error_code ec, std::size_t n){
                if(ec)
                    return;
                pipe2remote();
            }); });
    }

    void pipe2client()
    {
        auto self(shared_from_this());
        remote.async_read_some(boost::asio::buffer(to_client), [this, self](boost::system::error_code ec, std::size_t n)
                               {
			if (ec)
                return;
            boost::asio::async_write(client, boost::asio::buffer(to_client, n), [this, self](boost::system::error_code ec, std::size_t n){
                if(ec)
                    return;
                pipe2client();
            }); });
    }

private:
    std::vector<uint8_t> header;
    uint32_t VN, CD;
    uint8_t response[8];
    uint8_t to_client[BUF_SIZE], to_remote[BUF_SIZE];
    std::string DSTPORT;
    std::string DSTIP;
    tcp::socket client, remote;
};

class server
{
public:
    server(short port)
        : acceptor_(io_context)
    {
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket)
            {
                if (ec)
                    return;
                io_context.notify_fork(boost::asio::io_service::fork_prepare);
                pid_t pid = fork();
                while(pid == -1)
                    pid = fork();
                switch(pid){
                case -1:
                    perror("fork()");
                    return;
                case 0: // child
                    io_context.notify_fork(boost::asio::io_service::fork_child);
                    std::make_shared<session>(std::move(socket))
                        ->start();
                default: // parent
                    io_context.notify_fork(boost::asio::io_service::fork_parent);
                    do_accept();
                }
            });
    }

    tcp::acceptor acceptor_;
};

int main(int argc, char *argv[])
{
    try
    {
        if (argc != 2)
        {
            std::cerr << "Usage: http_server <port>\n";
            return 1;
        }

        server s(std::atoi(argv[1]));

        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}