#include <gtest/gtest.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sgx_error.h>
#include <sgx_uae_epid.h>
#include <sgx_ukey_exchange.h>
#include "enclave_u.h"

std::string host = "127.0.0.1";
static int guard_port = 8009;
static int _keymgr_socket;
static struct sockaddr_in addr;

sgx_enclave_id_t globalEnclaveId;
sgx_status_t status;
sgx_ra_context_t context = 0;

TEST(KMTest, testSetup) {
	// connect to KM
	_keymgr_socket = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GT(_keymgr_socket, 0);

	// create enclave
	sgx_launch_token_t sgxEnclaveToken = { 0 };
	ASSERT_EQ(sgx_create_enclave("enclave.sign.so",
				1,
				&sgxEnclaveToken,
				nullptr,
				&globalEnclaveId,
				nullptr),
				SGX_SUCCESS);

	ASSERT_EQ(enclave_init_ra(
				globalEnclaveId,
				&status,
				false,
				&context),
				SGX_SUCCESS);
	ASSERT_EQ(status, SGX_SUCCESS);

}

TEST(KMTest, testConnect) {
	addr.sin_family = AF_INET;
	addr.sin_port = htons(guard_port);
	ASSERT_GT(inet_pton(AF_INET, host.c_str(), &addr.sin_addr), 0);
	ASSERT_EQ(connect(_keymgr_socket, (struct sockaddr *)&addr, sizeof(addr)), 0);
}

TEST(KMTest, testAttestation) {
	uint32_t msg0_extended_epid_group_id = 0; // epid group id
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t p_msg2;
	sgx_ra_msg3_t* msg3;
	uint32_t msg3_len;

	// prepare msg0
	ASSERT_EQ(sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id), SGX_SUCCESS);

	// prepare msg1
	ASSERT_EQ(sgx_ra_get_msg1(context, globalEnclaveId, sgx_ra_get_ga, &msg1), SGX_SUCCESS);

	//send msg0 to KM
	ASSERT_GT(send(_keymgr_socket, &msg0_extended_epid_group_id, sizeof(msg0_extended_epid_group_id), 0), 0);

	// send msg1 to KM
	ASSERT_GT(send(_keymgr_socket, &msg1, sizeof(msg1), 0), 0);

	// get msg2 from KM
	ASSERT_GT(recv(_keymgr_socket, &p_msg2, sizeof(p_msg2), MSG_WAITALL), 0);

	// process msg2 to get msg3
	ASSERT_EQ(sgx_ra_proc_msg2(context,
								globalEnclaveId,
								sgx_ra_proc_msg2_trusted,
								sgx_ra_get_msg3_trusted,
								&p_msg2,
								sizeof(p_msg2),
								&msg3,
								&msg3_len),
								SGX_SUCCESS);

	 //send msg3 to KM
	 ASSERT_GT(send(_keymgr_socket, msg3, msg3_len, 0), 0);
}

TEST(KMTest, testTeardown) {
	ASSERT_EQ(close(_keymgr_socket), 0);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
