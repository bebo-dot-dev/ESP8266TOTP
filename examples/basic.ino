#include "ESP8266TOTP.h"

/*
 * this example uses a static point in time for test purposes
 * use NTP time in a real application to get true time based one time passwords calculated
 */
const uint64_t STATIC_EPOCH = 1480712707;

void setup()
{
	Serial.begin(115200, SERIAL_8N1);

	totpData data;

	if (ESP8266TOTP::GetNewKey(data.keyBytes)) {

		for(int i = 0; i < TOTP_SECRET_BYTE_COUNT; i++) {
			Serial.println(data.keyBytes[i]);
		}

		unsigned char data32[BASE_32_ENCODE_LENGTH];
		if (ESP8266TOTP::GetBase32Key(data.keyBytes, data32)) {

			Serial.println(reinterpret_cast<char*>(&data32));
			Serial.println(ESP8266TOTP::GetQrCodeImageUri(data.keyBytes, "Some host", "Some issuer"));

			int otp = ESP8266TOTP::GetTOTPToken(STATIC_EPOCH, data.keyBytes);
			Serial.println(otp);

			if (ESP8266TOTP::IsTokenValid(STATIC_EPOCH, data.keyBytes, otp)) {

				//this code path will always be taken in this test application
				//since we're basically comparing a firmware calculated OTP with the same
				//firmware calculated OTP passed as the ESP8266TOTP::IsTokenValid candidateOtp parameter.
				//In a real application, STATIC_EPOCH would be an NTP client determined epoch time value
				//and the ESP8266TOTP::IsTokenValid candidateOtp parameter would be supplied to the
				//firmware in some way i.e. as a HTTP form post value

				Serial.println("ESP8266TOTP::IsTokenValid..Yes it is!!");
			}

		} else {
			Serial.println("ESP8266TOTP::GetBase32Key failed");
		}

	} else {
		Serial.println("ESP8266TOTP::GetNewKey failed");
	}

}


void loop()
{

}
