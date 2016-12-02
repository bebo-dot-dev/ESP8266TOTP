/*
 * ESP8266TOTP.h
 *
 *  Created on: 18 Nov 2016
 *      Author: Joe
 *
 * An ESP8266 arduino core TOTP implementation compatible with rfc6238 and Google Authenticator
 *
 * Dependencies:
 * - Arduino.h, esp8266/arduino (https://github.com/esp8266/arduino)
 * - Base32.h, cpp-base32 for base32 functionality (https://github.com/jjssoftware/cpp-base32)
 * - sha1.h, Cryptosuite for sha1 and hmac functionality (https://github.com/jjssoftware/Cryptosuite)
 * - ESP8266TrueRandom.h, ESP8266TrueRandom for random number functionality (https://github.com/jjssoftware/ESP8266TrueRandom)
 *
 * Use UTC for the epoch parameter passed to methods in this class with no timezone offset
 *
 */

#ifndef ESP8266TOTP_H_
#define ESP8266TOTP_H_

#include "Base32.h"
#include "sha1.h"
#include "ESP8266TrueRandom.h"

#define TOTP_SECRET_BYTE_COUNT 16 //this implementation supports a secret key 16 bytes long
#define BASE_32_ENCODE_LENGTH Base32::GetEncode32Length(TOTP_SECRET_BYTE_COUNT)
#define TOTP_EPOCH_INTERVAL 30 //a otp lasts for 30 seconds

/*
 * the totpData struct intended for storage in flash
 */
struct totpData {
	bool enabled;								//TOTP global on/off switch
	uint8_t keyBytes[TOTP_SECRET_BYTE_COUNT];	//secret key bytes
} __attribute__ ((__packed__));

class ESP8266TOTP {
public:
	static bool ICACHE_FLASH_ATTR GetNewKey(uint8_t* keyBytes);
	static bool ICACHE_FLASH_ATTR GetBase32Key(uint8_t* keyBytes, unsigned char* data32);
	static uint8_t* ICACHE_FLASH_ATTR GetTOTPHMac(uint64_t epoch, uint8_t* keyBytes);
	static int ICACHE_FLASH_ATTR GetTOTPToken(uint64_t epoch, uint8_t* keyBytes);
	static bool ICACHE_FLASH_ATTR IsTokenValid(uint64_t epoch, uint8_t* keyBytes, int candidateOtp);
	static String ICACHE_FLASH_ATTR GetQrCodeImageUri(uint8_t* keyBytes, String hostname, String issuer);
private:
	static unsigned char base32Alphabet[];
	static const char* googleChartUriPre;
	static const char* googleChartUriSecret;
	static const char* googleChartUriIssuer;
};

#endif /* ESP8266TOTP_H_ */
