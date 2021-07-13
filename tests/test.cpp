#include <gtest/gtest.h>
#include <sys/socket.h>
#include <arpa/inet.h>

std::string host = "127.0.0.1";
static int guard_port = 8009;
static int _keymgr_socket;
static struct sockaddr_in addr;

TEST(KMTest, setUp) {
	_keymgr_socket = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GT(_keymgr_socket, 0);
}

TEST(KMTest, connect) {
	addr.sin_family = AF_INET;
	addr.sin_port = htons(guard_port);
	ASSERT_GT(inet_pton(AF_INET, host.c_str(), &addr.sin_addr), 0);
	ASSERT_EQ(connect(_keymgr_socket, (struct sockaddr *)&addr, sizeof(addr)), 0);
}

/*
TEST(KMTest, attest) {
	uint32_t msg0_extended_epid_group_id = 0; // epid group id
	sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id)
	//send msg0 to KM
	send(_keymgr_socket, &msg0_extended_epid_group_id, sizeof(msg0_extended_epid_group_id), 0);
}*/

TEST(KMTest, tearDown) {
	ASSERT_EQ(close(_keymgr_socket), 0);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
