CXX=g++
CXXFLAGS=-std=c++14 -Wall -pedantic -pthread -lboost_system
CXX_INCLUDE_DIRS=/usr/local/include
CXX_INCLUDE_PARAMS=$(addprefix -I , $(CXX_INCLUDE_DIRS))
CXX_LIB_DIRS=/usr/local/lib
CXX_LIB_PARAMS=$(addprefix -L , $(CXX_LIB_DIRS))

all: socks_server hw4.cgi

socks_server: socks_server.cpp
	$(CXX) $< -o $@ $(CXX_INCLUDE_PARAMS) $(CXX_LIB_PARAMS) $(CXXFLAGS) -g

hw4.cgi: console.cpp
	$(CXX) $< -o $@ $(CXX_INCLUDE_PARAMS) $(CXX_LIB_PARAMS) $(CXXFLAGS) -g

clean:
	rm -f socks_server hw4.cgi

format:
	clang-format -i *.cpp *.hpp --style=file

install: socks_server hw4.cgi
	cp hw4.cgi ~/public_html
	cp panel_socks.cgi ~/public_html
	cp -r test_case/ ~/public_html
	@echo http://nplinux1.cs.nycu.edu.tw/~xbwu90317/panel_socks.cgi

np_single_golden:
	rm -rf np_single/working_dir
	cp -r np_single/working_dir_template np_single/working_dir
	cd np_single/working_dir && ./np_single_golden 25569