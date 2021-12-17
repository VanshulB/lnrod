use lnrod::tor::server::test_onion_server;

fn main() {
	test_onion_server().expect("success");
}
