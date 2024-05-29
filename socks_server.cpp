#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <cstring>
#include <regex>
#include <sys/wait.h>
#include <fstream>

boost::asio::io_context io_context;

using boost::asio::ip::tcp;

#define BUF_SIZE 1024

void clean_zombies()
{
    while (waitpid(-1, nullptr, WNOHANG) > 0)
        ;
}

bool firewall_check(char kind, const std::string& ip)
{
    std::ifstream rules("./socks.conf");
    if (!rules.is_open()) {
        std::ofstream outfile("./socks.conf");
        if (outfile) {
            outfile << "permit c *.*.*.*\n";
            outfile << "permit b *.*.*.*\n";
            return true;
        }
        return false;
    }
        

    std::string rule;
    while (std::getline(rules, rule))
    {
        while(rule.back() == '\r' || rule.back() == '\r')
            rule.pop_back();
        if (rule.size() == 0)
            continue;
        char *r = &rule[0];
        char *permit = strtok_r(r, " ", &r);
        if (strcmp(permit, "permit"))
            continue;
        char kind_ = strtok_r(r, " ", &r)[0];
        if (kind != kind_)
            continue;
        char *mask = strtok_r(r, " ", &r);
        if (!mask)
            continue;
        std::string sdjkfahd(ip);
        char *ip_ = &sdjkfahd[0];;
        while (*mask && *ip_)
        {
            std::string m(strtok_r(mask, ".", &mask));
            std::string p(strtok_r(ip_, ".", &ip_));
            if (m != "*" && p != m)
                goto check_next_rule;
        }
        return true;
    check_next_rule:
        continue;
    }
    return false;
}

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
        try
        {
            auto self(shared_from_this());
            boost::asio::read_until(client, boost::asio::dynamic_buffer(header), socks4a_match());
            parse_header();
        }
        catch (std::exception &e)
        {
            return;
        }
    }

    void set_dst() {
        DSTPORT = std::to_string(header[2] << 8 | header[3]);;

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
        if (!memcmp(&header[4], "\0\0\0", 3) && header[7])
        {
            tcp::resolver resovler(io_context);
            remote_ips = resovler.resolve(std::string((char *)&header[first]), DSTPORT);
            return;
        }
        else
        {
            DSTIP = std::to_string((uint32_t)header[4]) + ".";
            DSTIP += std::to_string((uint32_t)header[5]) + ".";
            DSTIP += std::to_string((uint32_t)header[6]) + ".";
            DSTIP += std::to_string((uint32_t)header[7]);
            tcp::resolver resovler(io_context);
            remote_ips = resovler.resolve(DSTIP, DSTPORT);
            return;
        }
    }

    void reply(uint8_t cd, uint16_t port) {
        memset(response, 0, 8);
        response[1] = cd;
        memcpy(response + 2, &port, 2);
        std::swap(response[2], response[3]);
        boost::asio::write(client, boost::asio::buffer(response, 8));
    }

    void log(bool accepted) {
        std::cout << "<S_IP>: " << client.remote_endpoint().address() << "\n";
        std::cout << "<S_PORT>: " << client.remote_endpoint().port() << "\n";
        std::cout << "<D_IP>: " << DSTIP << "\n";
        std::cout << "<D_PORT>: " << DSTPORT << "\n";
        std::cout << "<Command>: " << (CD == 1 ? "CONNECTION\n" : "BIND\n");
        std::cout << "<Reply>: " << (accepted ? "Accept\n\n" : "Reject\n\n");
    }

    void parse_header()
    {
        auto self(shared_from_this());
        VN = header[0];
        CD = header[1];
        if (VN != 4 || (CD != 1 && CD != 2)) {
            return;
        }
        
        set_dst();

        if (CD == 1)
        {
            for(auto ip : remote_ips){
                DSTIP = ip.endpoint().address().to_string();
                if(firewall_check('c', DSTIP)) {
                    boost::asio::connect(remote, remote_ips);
                    break;
                }
            }
        
            if(remote.is_open()) {
                reply(90, 0);
                log(true);
                pipe2remote();
                pipe2client();
            } else {
                reply(91, 0);
                log(false);
            }
        }
        else
        {
            bool accepted = false;
            for(auto ip : remote_ips){
                DSTIP = ip.endpoint().address().to_string();
                if(firewall_check('b', DSTIP)) {
                    accepted = true;
                }
            }
            

            tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 0));
            auto port = acceptor.local_endpoint().port();

            if(!accepted) {
                log(false);
                reply(91, 0);
                return;
            }
            
            reply(90, port);

            acceptor.accept(remote);
                    
            accepted = false;
            for(auto ip : remote_ips) {
                if(remote.remote_endpoint().address().to_string() == ip.endpoint().address().to_string())
                    accepted = true;
            }

            if(accepted) {
                reply(90, port);
                log(true);
                pipe2remote();
                pipe2client();
            }
            else
            {
                reply(91, 0);
                log(false);
            }
        }
    }

    void pipe2remote()
    {
        auto self(shared_from_this());
        client.async_read_some(boost::asio::buffer(to_remote), [this, self](boost::system::error_code ec, std::size_t n)
                               {
			if (ec){
                remote.close();
                return;
            }
            boost::asio::async_write(remote, boost::asio::buffer(to_remote, n), [this, self](boost::system::error_code ec, std::size_t n){
                if (ec){
                    client.close();
                    return;
                }
                pipe2remote();
            }); });
    }

    void pipe2client()
    {
        auto self(shared_from_this());
        remote.async_read_some(boost::asio::buffer(to_client), [this, self](boost::system::error_code ec, std::size_t n)
                               {
			if (ec){
                client.close();
                return;
            }
                
            boost::asio::async_write(client, boost::asio::buffer(to_client, n), [this, self](boost::system::error_code ec, std::size_t n){
                if (ec){
                    remote.close();
                    return;
                }
                pipe2client();
            }); });
    }

private:
    boost::asio::ip::basic_resolver_results<tcp> remote_ips;
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
                while (pid == -1)
                    pid = fork();
                switch (pid)
                {
                case -1:
                    perror("fork()");
                    return;
                case 0: // child
                    io_context.notify_fork(boost::asio::io_service::fork_child);
                    std::make_shared<session>(std::move(socket))
                        ->start();
                    return;
                default: // parent
                    io_context.notify_fork(boost::asio::io_service::fork_parent);
                    clean_zombies();
                    do_accept();
                    return;
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