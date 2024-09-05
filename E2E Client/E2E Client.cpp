#include <thread>
#include <iostream>
#include <enet/enet.h>
#include <SFML/Network/Packet.hpp>

#include <cryptlib.h>
#include <rng.h>
#include <osrng.h>
#include <hex.h>
#include <rsa.h>
#include <blake2.h>
#include <cassert>

#define RAND_BLOCK_SIZE 1536

std::string TargetServerIP = "localhost";
std::string HostServerIP = "localhost";

enet_uint16 port = 23180;

bool bServerThreadRunning = false;
bool bClientThreadRunning = false;
void ClientKeyboardThread();
void ServerKeyboardThread();

enum {
	HEARTBEAT_SEND,
	HEARTBEAT_ACK,

	MESSAGE
};

ENetPacket* CreatePacket( sf::Packet* pPacket ) {
	return enet_packet_create( pPacket->getData(), pPacket->getDataSize(), ENET_PACKET_FLAG_RELIABLE );
}

void CreateAndSendPacket( ENetPeer* pPeer, sf::Packet* pPacket ) {
	enet_peer_send( pPeer, NULL, CreatePacket( pPacket ) );
}

class TextMessage {
public:
	TextMessage() {
	}
	TextMessage( std::string* sInputMessage, std::string* sInputPublicKey ) {
		sMessage = *sInputMessage;
		sPublicKey = *sInputPublicKey;
		this->HashInputMessage();
	}

	void EncryptMessage( std::string* sInputMessage, std::string* sInputPublicKey ) {
		// Set class variables
		sMessage = *sInputMessage;
		sPublicKey = *sInputPublicKey;

		// Hash the input message
		this->HashInputMessage();

		// Setup encryption
		CryptoPP::AutoSeededRandomPool RNG;
		CryptoPP::RSAES_PKCS1v15_Encryptor Encrypt;

		CryptoPP::StringSource Decode( *sInputPublicKey, true );
		Encrypt.AccessPublicKey().Load( Decode );

		// Encrypt message
		std::string tempString;
		CryptoPP::StringSource tempStringSource( sMessage, true,
			new CryptoPP::PK_EncryptorFilter( RNG, Encrypt,
				new CryptoPP::StringSink( tempString )
			)
		);
		sMessage = tempString;

		// Encrypt hash
		tempString.clear();
		CryptoPP::StringSource tempStringSourceHash( sHash, true,
			new CryptoPP::PK_EncryptorFilter( RNG, Encrypt,
				new CryptoPP::StringSink( tempString )
			)
		);
		sHash = tempString;
	}

	void DecryptMessage( std::string* sInputPrivateKey ) {
		// Setup decryption
		CryptoPP::AutoSeededRandomPool RNG;
		CryptoPP::RSAES_PKCS1v15_Decryptor Decrypt;

		CryptoPP::StringSource Decode( *sInputPrivateKey, true );
		Decrypt.AccessPrivateKey().Load( Decode );

		// Decrypt message
		std::string tempString;
		CryptoPP::StringSource tempStringSource( sMessage, true,
			new CryptoPP::PK_DecryptorFilter( RNG, Decrypt,
				new CryptoPP::StringSink( tempString )
			)
		);
		sMessage = tempString;

		// Decrypt hash
		tempString.clear();
		CryptoPP::StringSource tempStringSourceHash( sHash, true,
			new CryptoPP::PK_DecryptorFilter( RNG, Decrypt,
				new CryptoPP::StringSink( tempString )
			)
		);
		sHash = tempString;

		// See if the message was successfully sent and received
		assert( this->VerifyHash() );
	}

	// Can return both encrypted and decrypted
	std::string& GetTextMessage() {
		return sMessage;
	}

	// Can return both encrypted and decrypted, should be hash of unencrypted message
	std::string& GetHash() {
		return sHash;
	}

	// Public key is never encrypted
	std::string& GetPublicKey() {
		return sPublicKey;
	}

	bool VerifyHash() {
		CryptoPP::BLAKE2b BlakeHash;
		BlakeHash.Update( ( CryptoPP::byte* )sMessage.data(), sMessage.size() );
		return BlakeHash.Verify( ( CryptoPP::byte* )sHash.data() );
	}

	int Size() {
		return sMessage.size() + sHash.size() + sPublicKey.size();
	}

private:
	// We're going to have to encrypt the hash. Blake is not meant for storing private information
	void HashInputMessage() {
		// Hash the input message
		CryptoPP::BLAKE2b BlakeHash;
		BlakeHash.Update( ( CryptoPP::byte* )sMessage.data(), sMessage.size() );

		sHash.resize( BlakeHash.DigestSize() );
		BlakeHash.Final( ( CryptoPP::byte* )sHash.data() );
	}

private:
	// Encrypt message and hash, only exposing the public key
	std::string sMessage;
	// Hash is the hash of the unencrypted message
	std::string sHash;

	// Never encrypt (how are we identifiying keys then?)
	std::string sPublicKey;
};

class RSAKeys {
public:
	RSAKeys() {
		CryptoPP::AutoSeededRandomPool RNG;
		CryptoPP::InvertibleRSAFunction Params;

		// Client keys
		Params.GenerateRandomWithKeySize( RNG, RAND_BLOCK_SIZE );
		pPublicKey = CryptoPP::RSA::PublicKey( Params );
		pPrivateKey = CryptoPP::RSA::PrivateKey( Params );

		CryptoPP::StringSink publicSink( sPublicKey );
		pPublicKey.Save( publicSink );

		CryptoPP::StringSink privateSink( sPrivateKey );
		pPrivateKey.Save( privateSink );
	}

public:
	CryptoPP::RSA::PublicKey pPublicKey;
	std::string sPublicKey;

	CryptoPP::RSA::PrivateKey pPrivateKey;
	std::string sPrivateKey;
};

std::string ServerPeerPublicKey;
ENetPeer* pLastPeer = nullptr;
void createServer() {
	ENetAddress ServerAddress;
	//ServerAddress.host = ENET_HOST_ANY;
	enet_address_set_host( &ServerAddress, HostServerIP.c_str() );
	ServerAddress.port = port;

	ENetHost* pServer = enet_host_create( &ServerAddress, 1, 2, 0, 0 );
	if ( !pServer ) {
		fprintf( stderr, "An error occurred while trying to create an ENet server host.\n" );
		bServerThreadRunning = false;

		system( "pause" );
		return exit( EXIT_FAILURE );
	}

	char ServerIP[32];
	int status = enet_address_get_host_ip( &ServerAddress, ServerIP, sizeof( ServerIP ) );
	std::cout << "Server Status: " << status << ", IP: " << ServerIP << ":" << ServerAddress.port << std::endl;

	status = enet_address_get_host_ip( &pServer->address, ServerIP, sizeof( ServerIP ) );
	std::cout << "Server Status: " << status << ", IP: " << ServerIP << ":" << pServer->address.port << std::endl;

	std::thread createKeyboardThread( ServerKeyboardThread );
	createKeyboardThread.detach();

	bool bRunning = true;
	bool bHeartBeatReply = true;
	int iHeartBeatFailures = 0;

	RSAKeys ServerPrivateKeys;
	ENetEvent Event;
	while ( bRunning ) {
		if ( GetAsyncKeyState( VK_OEM_6 ) )
			bRunning = false;

		int iStatus = enet_host_service( pServer, &Event, NULL );

		if ( !iStatus ) {
			sf::Packet HeartBeatPacket;
			HeartBeatPacket << HEARTBEAT_SEND << ServerPrivateKeys.sPublicKey;
			enet_host_broadcast( pServer, NULL, CreatePacket( &HeartBeatPacket ) );

			if ( !bHeartBeatReply && iHeartBeatFailures > 4 ) {
				//bRunning = false;
			} else {
				bHeartBeatReply = false;

				if ( iHeartBeatFailures > 2 )
					printf( "Server HeartBeatFailures: %i\n", iHeartBeatFailures );

				iHeartBeatFailures++;
			}
		}

		while ( iStatus > 0 || enet_host_service( pServer, &Event, NULL ) > 0 ) {
			iStatus = 0;

			switch ( Event.type ) {
				case ENET_EVENT_TYPE_CONNECT: {
					printf( "Server: A new client connected from %x:%u.\n",
						Event.peer->address.host,
						Event.peer->address.port );
					break;
				}
				case ENET_EVENT_TYPE_DISCONNECT: {
					printf( "Server: %s disconnected.\n", Event.peer->data );
					break;
				}
				case ENET_EVENT_TYPE_RECEIVE: {
					pLastPeer = Event.peer;

					sf::Packet Packet;
					Packet.append( Event.packet->data, Event.packet->dataLength );

					int ID;
					Packet >> ID;

					//std::cout << "Server receive ID: " << ID << std::endl;

					if ( ID == HEARTBEAT_SEND ) {
						Packet >> ServerPeerPublicKey;

						sf::Packet ReplyPacket;
						ReplyPacket << HEARTBEAT_ACK;
						CreateAndSendPacket( Event.peer, &ReplyPacket );
						bHeartBeatReply = true;
						iHeartBeatFailures = 0;
					} else if ( ID == MESSAGE ) {
						TextMessage Message;
						Packet >> Message.GetTextMessage() >> Message.GetHash() >> Message.GetPublicKey();

						Message.DecryptMessage( &ServerPrivateKeys.sPrivateKey );

						std::cout << "Server receive Message: " << Message.GetTextMessage() << std::endl;
					}

					enet_packet_destroy( Event.packet );
					break;
				}
			}
		}

		Sleep( 100 );
	}

	// Exit
	printf( "Server Shutdown\n" );
	enet_host_destroy( pServer );
	bServerThreadRunning = false;
}

std::string ClientPeerPublicKey;
ENetPeer* pServerPeer = nullptr;
void createClient() {
	ENetHost* pClient = enet_host_create( NULL, 1, 2, 0, 0 );
	if ( !pClient ) {
		fprintf( stderr, "An error occurred while trying to create an ENet client host.\n" );
		bClientThreadRunning = false;

		system( "pause" );
		return exit( EXIT_FAILURE );
	}

	ENetAddress ServerAddress;
	enet_address_set_host( &ServerAddress, TargetServerIP.c_str() );
	ServerAddress.port = port;

	pServerPeer = enet_host_connect( pClient, &ServerAddress, 2, 0 );
	if ( !pServerPeer ) {
		fprintf( stderr, "No available peers for initiating an ENet connection.\n" );
		bClientThreadRunning = false;

		system( "pause" );
		return exit( EXIT_FAILURE );
	}

	std::thread createKeyboardThread( ClientKeyboardThread );
	createKeyboardThread.detach();

	bool bRunning = true;
	bool bHeartBeatReply = true;
	int iHeartBeatFailures = 0;

	RSAKeys ClientPrivateKeys;
	ENetEvent Event;
	while ( bRunning ) {
		if ( GetAsyncKeyState( VK_OEM_4 ) ) {
			enet_peer_disconnect( pServerPeer, NULL );
			bRunning = false;
		}

		int iStatus = enet_host_service( pClient, &Event, NULL );

		if ( !iStatus ) {
			sf::Packet HeartBeatPacket;
			HeartBeatPacket << HEARTBEAT_SEND << ClientPrivateKeys.sPublicKey;
			CreateAndSendPacket( pServerPeer, &HeartBeatPacket );

			if ( !bHeartBeatReply && iHeartBeatFailures > 4 ) {
				enet_peer_disconnect( pServerPeer, NULL );
				bRunning = false;
			} else {
				bHeartBeatReply = false;

				if ( iHeartBeatFailures > 2 )
					printf( "Client HeartBeatFailures: %i\n", iHeartBeatFailures );

				iHeartBeatFailures++;
			}
		}

		while ( iStatus > 0 || enet_host_service( pClient, &Event, NULL ) > 0 ) {
			iStatus = 0;

			switch ( Event.type ) {
				case ENET_EVENT_TYPE_CONNECT: {
					printf( "Client: A new client connected from %x:%u.\n",
						Event.peer->address.host,
						Event.peer->address.port );
					break;
				}
				case ENET_EVENT_TYPE_DISCONNECT: {
					printf( "Client: %s disconnected.\n", Event.peer->data );
					break;
				}
				case ENET_EVENT_TYPE_RECEIVE: {
					sf::Packet Packet;
					Packet.append( Event.packet->data, Event.packet->dataLength );

					int ID;
					Packet >> ID;

					//std::cout << "Client receive ID: " << ID << std::endl;

					if ( ID == HEARTBEAT_SEND ) {
						Packet >> ClientPeerPublicKey;

						sf::Packet ReplyPacket;
						ReplyPacket << HEARTBEAT_ACK;
						CreateAndSendPacket( pServerPeer, &ReplyPacket );
						bHeartBeatReply = true;
						iHeartBeatFailures = 0;
					} else if ( ID == MESSAGE ) {
						TextMessage Message;
						Packet >> Message.GetTextMessage() >> Message.GetHash() >> Message.GetPublicKey();

						Message.DecryptMessage( &ClientPrivateKeys.sPrivateKey );

						std::cout << "Client receive Message: " << Message.GetTextMessage() << std::endl;
					}

					enet_packet_destroy( Event.packet );
					break;
				}
			}
		}

		Sleep( 100 );
	}

	// Exit
	printf( "Client Shutdown\n" );
	enet_host_destroy( pClient );
	bClientThreadRunning = false;
}

void ClientKeyboardThread() {
	if ( !pServerPeer )
		return;

	while ( bClientThreadRunning ) {
		char InputChat[8192];
		std::cin.clear();
		std::cin.getline( InputChat, sizeof( InputChat ) );
		std::string Chat = InputChat;

		if ( Chat.size() ) {
			TextMessage Message( &Chat, &ClientPeerPublicKey );
			Message.EncryptMessage( &Message.GetTextMessage(), &ClientPeerPublicKey );

			sf::Packet ReplyPacket;
			ReplyPacket << MESSAGE << Message.GetTextMessage() << Message.GetHash() << Message.GetPublicKey();
			CreateAndSendPacket( pServerPeer, &ReplyPacket );
		}
	}
}

void ServerKeyboardThread() {
	while ( bServerThreadRunning ) {
		char InputChat[8192];
		std::cin.clear();
		std::cin.getline( InputChat, sizeof( InputChat ) );
		std::string Chat = InputChat;

		if ( pLastPeer && Chat.size() ) {
			TextMessage Message( &Chat, &ServerPeerPublicKey );
			Message.EncryptMessage( &Message.GetTextMessage(), &ServerPeerPublicKey );

			sf::Packet ReplyPacket;
			ReplyPacket << MESSAGE << Message.GetTextMessage() << Message.GetHash() << Message.GetPublicKey();
			CreateAndSendPacket( pLastPeer, &ReplyPacket );
		}
	}
}

int main() {
	if ( enet_initialize() != 0 ) {
		fprintf( stderr, "An error occurred while initializing ENet.\n" );
		return EXIT_FAILURE;
	}

	char cInputChar = 'n';

	std::cout << "Become the host? (y/n)" << std::endl;
	std::cin >> cInputChar;

	switch ( cInputChar ) {
		case 'y': {
			std::cout << "Enter the server's IP: " << std::endl;
			std::cin >> HostServerIP;

			std::cout << "Enter the server's port: " << std::endl;
			std::cin >> port;

			std::cout << "Creating host: " << HostServerIP << ":" << port << std::endl;

			bServerThreadRunning = true;
			std::thread createServerThread( createServer );
			createServerThread.detach();
			break;
		}

		default: {
			std::cout << "Enter the IP to connect to: " << std::endl;
			std::cin >> TargetServerIP;

			std::cout << "Enter the server's port: " << std::endl;
			std::cin >> port;

			std::cout << "Connecting to: " << TargetServerIP << ":" << port << std::endl;

			bClientThreadRunning = true;
			std::thread createClientThread( createClient );
			createClientThread.detach();
			break;
		}
	}

	while ( bServerThreadRunning || bClientThreadRunning )
		std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );

	std::cout << "Exiting" << std::endl;
	system( "pause" );
	return atexit( enet_deinitialize );
}