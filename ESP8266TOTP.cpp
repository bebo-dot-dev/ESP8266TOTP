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

#include "ESP8266TOTP.h"

//RFC 4648 defined 'standard' Base32 base32Alphabet
unsigned char ESP8266TOTP::base32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

//Google char QR code uri parts
const char* ESP8266TOTP::googleChartUriPre = "https://chart.googleapis.com/chart?chs=225x225&cht=qr&chl=200x200&chld=M|0&chl=otpauth://totp/user@";
const char* ESP8266TOTP::googleChartUriSecret = "%3Fsecret%3D";
const char* ESP8266TOTP::googleChartUriIssuer = "%26issuer%3D";

/*
 * returns a new secret key of made up of random bytes of TOTP_SECRET_BYTE_COUNT length
 * into the supplied keyBytes buffer
 */
bool ICACHE_FLASH_ATTR ESP8266TOTP::GetNewKey(uint8_t* keyBytes) {

	for(int i = 0; i < TOTP_SECRET_BYTE_COUNT; i++) {
		char rndByte = ESP8266TrueRandom.randomByte();
		keyBytes[i] = rndByte;
	}

	return true;

}

/*
 * converts the given keyBytes to a base32 representation into the supplied data32 buffer
 */
bool ICACHE_FLASH_ATTR ESP8266TOTP::GetBase32Key(uint8_t* keyBytes, unsigned char* data32) {

	if (Base32::Encode32(keyBytes, TOTP_SECRET_BYTE_COUNT, data32)) {
		return Base32::Map32(data32, BASE_32_ENCODE_LENGTH, ESP8266TOTP::base32Alphabet);
	}

	return false;

}

/*
 * returns a TOTP hashed message authentication code for the given epoch point in time and secret key bytes
 */
uint8_t* ICACHE_FLASH_ATTR ESP8266TOTP::GetTOTPHMac(uint64_t epoch, uint8_t* keyBytes) {

	uint64_t time = epoch / TOTP_EPOCH_INTERVAL;

	uint8_t timeBytes[8];
	timeBytes[0] = 0x00;
	timeBytes[1] = 0x00;
	timeBytes[2] = 0x00;
	timeBytes[3] = 0x00;
	timeBytes[4] = (int)((time >> 24) & 0xFF) ;
	timeBytes[5] = (int)((time >> 16) & 0xFF) ;
	timeBytes[6] = (int)((time >> 8) & 0XFF);
	timeBytes[7] = (int)((time & 0XFF));

	Sha1.initHmac(keyBytes, TOTP_SECRET_BYTE_COUNT);
	for (int i = 0; i < 8; i++)
	{
		Sha1.write(timeBytes[i]);
	}

	return Sha1.resultHmac();

}

/*
 * returns the TOTP token for the given epoch point in time and secret key bytes
 */
int ICACHE_FLASH_ATTR ESP8266TOTP::GetTOTPToken(uint64_t epoch, uint8_t* keyBytes) {

	uint8_t *hash = ESP8266TOTP::GetTOTPHMac(epoch, keyBytes);

	int offset = hash[19] & 0xF;
	int otp = 0;
	for (int i = 0; i < 4; ++i)
	{
		otp = otp << 8;
		otp = otp | hash[offset + i];
	}
	otp = otp & 0x7FFFFFFF;
	otp = otp % 1000000;

	return otp;

}

/*
 * calculates the TOTP token for the given epoch point in time and secret key bytes and returns
 * an indicator whether that calculated TOTP token and the given candidateOtp exactly match
 */
bool ICACHE_FLASH_ATTR ESP8266TOTP::IsTokenValid(uint64_t epoch, uint8_t* keyBytes, int candidateOtp) {

	int otp = ESP8266TOTP::GetTOTPToken(epoch, keyBytes);
	return otp == candidateOtp;

}

/*
 * returns a Google Authenticator key uri format compatible uri for the given keyBytes
 * intended for rendering a QR code in a web page.
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * This method exists to enable an easy way to add your secret key to Google Authenticator.
 * If you use this method to render a QR code for your secret key into a web page, ensure
 * that web page is served over TLS. Also consider implementing addition security rules around
 * showing the QR code.
 */
String ICACHE_FLASH_ATTR ESP8266TOTP::GetQrCodeImageUri(uint8_t* keyBytes, String hostname, String issuer) {

	String outStr;
	unsigned char data32[BASE_32_ENCODE_LENGTH];

	if (ESP8266TOTP::GetBase32Key(keyBytes, data32)) {

		char* base32Key = reinterpret_cast<char*>(&data32);

		outStr = String(ESP8266TOTP::googleChartUriPre);
		outStr += hostname;
		outStr += ESP8266TOTP::googleChartUriSecret;
		outStr += String(base32Key);
		outStr += ESP8266TOTP::googleChartUriIssuer;
		outStr += issuer;

	}

	return outStr;
}

