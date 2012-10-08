
GTEST_DIR = /Users/ranzhao1/Desktop/IBE_GitHub/src/gtest

# Where to find user code.
USER_DIR = /Users/ranzhao1/Desktop/IBE_GitHub/src/BasicIdent_FullIdent


# Flags passed to the preprocessor.
CPPFLAGS += -I$(GTEST_DIR)/include

# Flags passed to the C++ compiler.
CXXFLAGS += -g -Wall -Wextra  -I /usr/local/include/  -L /usr/local/lib/ -Wl,-rpath /usr/local/lib -l pbc -l gmp



TESTS = bf_4_1_unittest


GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h

# House-keeping build targets.

all : $(TESTS)

clean :
	rm -f $(TESTS) gtest.a gtest_main.a *.o

# Builds gtest.a and gtest_main.a.


GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^


sha1.o: $(USER_DIR)/sha1.h $(USER_DIR)/sha1.cc $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/sha1.cc

bf_4_1.o : $(USER_DIR)/bf_4_1.cc $(USER_DIR)/bf_4_1.h sha1.o  $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/bf_4_1.cc 

bf_4_1_unittest.o : $(USER_DIR)/bf_4_1_unittest.cc $(USER_DIR)/bf_4_1.h $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/bf_4_1_unittest.cc

bf_4_1_unittest : bf_4_1_unittest.o bf_4_1.o sha1.o gtest_main.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lpthread $^ -o $@