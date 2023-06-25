#include "aes.c"
#include <LoRa.h>
#include <LoRandom.h>

/*
  Note: I have "customized" the LoRa library by moving
  uint8_t readRegister(uint8_t address);
  void writeRegister(uint8_t address, uint8_t value);
  to public: in LoRa.h – as we need access to the registers, obviously.
*/

void writeRegister(uint8_t reg, uint8_t value) {
  LoRa.writeRegister(reg, value);
}
uint8_t readRegister(uint8_t reg) {
  return LoRa.readRegister(reg);
}

char encBuf[256] = {0}; // Let's make sure we have enough space for the encrypted string
char decBuf[256] = {0}; // Let's make sure we have enough space for the decrypted string
char plainBuf[256] = {0}; // Let's make sure we have enough space for the decrypted string
/* Plaintext */
uint8_t aPlaintextECB[64] = {
  0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
  0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
  0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
  0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
  0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
  0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
  0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
  0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

uint8_t aPlaintextCBC[64] = {
  0xE2, 0xBE, 0xC1, 0x6B, 0x96, 0x9F, 0x40, 0x2E,
  0x11, 0x7E, 0x3D, 0xE9, 0x2A, 0x17, 0x93, 0x73,
  0x57, 0x8A, 0x2D, 0xAE, 0x9C, 0xAC, 0x03, 0x1E,
  0xAC, 0x6F, 0xB7, 0x9E, 0x51, 0x8E, 0xAF, 0x45,
  0x46, 0x1C, 0xC8, 0x30, 0x11, 0xE4, 0x5C, 0xA3,
  0x19, 0xC1, 0xFB, 0xE5, 0xEF, 0x52, 0x0A, 0x1A,
  0x45, 0x24, 0x9F, 0xF6, 0x17, 0x9B, 0x4F, 0xDF,
  0x7B, 0x41, 0x2B, 0xAD, 0x10, 0x37, 0x6C, 0xE6
};

/* AES_ECB */
/* Expected text: Encrypted Data with AES 128 Mode ECB */
uint8_t aEncryptedtextECB128[64] = {
  0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60,
  0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
  0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D,
  0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
  0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23,
  0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
  0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F,
  0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4,

};

/*AES_CBC*/
/* Expected text: Encrypted Data with AES 128 Mode CBC */
uint8_t aEncryptedtextCBC128[64] = {
  0xAC, 0xAB, 0x49, 0x76, 0x46, 0xB2, 0x19, 0x81,
  0x9B, 0x8E, 0xE9, 0xCE, 0x7D, 0x19, 0xE9, 0x12,
  0x9B, 0xCB, 0x86, 0x50, 0xEE, 0x19, 0x72, 0x50,
  0x3A, 0x11, 0xDB, 0x95, 0xB2, 0x78, 0x76, 0x91,
  0xB8, 0xD6, 0xBE, 0x73, 0x3B, 0x74, 0xC1, 0xE3,
  0x9E, 0xE6, 0x16, 0x71, 0x16, 0x95, 0x22, 0x22,
  0xA1, 0xCA, 0xF1, 0x3F, 0x09, 0xAC, 0x1F, 0x68,
  0x30, 0xCA, 0x0E, 0x12, 0xA7, 0xE1, 0x86, 0x75,

};

uint8_t AESIV[16] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B,
  0x0C, 0x0D, 0x0E, 0x0F,
};

uint8_t pKey[16] = {0};
uint8_t pKeyAES[16] = {
  0x2B, 0x7E, 0x15, 0x16,
  0x28, 0xAE, 0xD2, 0xA6,
  0xAB, 0xF7, 0x15, 0x88,
  0x09, 0xCF, 0x4F, 0x3C,
};
uint8_t Iv[16] = {0};
uint8_t pKeyLen = 16;

void setup() {
  Serial.begin(115200);
  uint32_t timeout = millis();
  while (!Serial) {
    if ((millis() - timeout) < 5000) {
      delay(100);
    } else {
      break;
    }
  }
  delay(2000);
  Serial.printf("\nRAK811 Software AES%d test!\n", (AES_KEYLEN * 8));
  Serial.println(F(" - [SX1278] Initializing ... "));
  delay(1000);
  pinMode(RADIO_XTAL_EN, OUTPUT); //Power LoRa module
  digitalWrite(RADIO_XTAL_EN, HIGH);
  LoRa.setPins(RADIO_NSS, RADIO_RESET, RADIO_DIO_0);
  if (!LoRa.begin(470e6)) {
    Serial.println("Starting LoRa failed!");
    while (1);
  }
  LoRa.setTxPower(20, PA_OUTPUT_PA_BOOST_PIN);
  LoRa.setPreambleLength(8);
  LoRa.setTxPower(20, PA_OUTPUT_PA_BOOST_PIN);
  LoRa.setPreambleLength(8);
  LoRa.setSpreadingFactor(12);
  LoRa.setSignalBandwidth(250E3);
  LoRa.setCodingRate4(5);
  pinMode(RADIO_RF_CRX_RX, OUTPUT);
  digitalWrite(RADIO_RF_CRX_RX, HIGH); // set LoRa to receive
  pinMode(RADIO_RF_CTX_PA, OUTPUT);
  digitalWrite(RADIO_RF_CTX_PA, LOW);

  Serial.print(F(" - [SX1278] Building Iv...\n"));
  fillRandom(Iv, 16);
  hexDump((unsigned char *)Iv, 16);
  Serial.print(F(" - [SX1278] Building Key...\n"));
  fillRandom(pKey, 16);
  hexDump((unsigned char *)pKey, 16);

  char *msg = "Hello user! This is a plain text string!";
  uint8_t msgLen = strlen(msg) + 1; // Include '\0'
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  Serial.println("pKey:");
  hexDump(pKey, 16);

  uint16_t olen, counter = 0;
  double t0 = millis() + 1000;
  while (millis() < t0) {
    olen = encryptECB((uint8_t*)msg, msgLen);
    counter++;
  }
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);
  memcpy(decBuf, encBuf, olen);

  t0 = millis() + 1000;
  counter = 0;
  while (millis() < t0) {
    olen = decryptECB((uint8_t*)decBuf, olen);
    counter++;
  }
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);

  Serial.println("IV:");
  hexDump(Iv, 16);
  strcpy(plainBuf, msg);
  counter = 0;
  t0 = millis() + 1000;
  while (millis() < t0) {
    encryptCBC((uint8_t*)plainBuf, msgLen, Iv);
    counter++;
  }
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, olen);
  Serial.printf("%d round / s\n", counter);
  memcpy(decBuf, encBuf, olen);
  counter = 0;
  t0 = millis() + 1000;
  while (millis() < t0) {
    decryptCBC((uint8_t*)encBuf, olen, Iv);
    counter++;
  }
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, olen);
  Serial.printf("%d round / s\n", counter);

  // 64-byte test
  memcpy(pKey, pKeyAES, 16);
  memcpy(Iv, AESIV, 16);
  Serial.println(F("=============================="));
  Serial.println(F("        64-Byte TEST"));
  Serial.println(F("=============================="));
  Serial.println("ECB Plaintext:");
  hexDump((unsigned char *)aPlaintextECB, 64);
  Serial.println("ECB Ciphertext:");
  hexDump((unsigned char *)aEncryptedtextECB128, 64);

  counter = 0;
  memcpy(encBuf, aPlaintextECB, 64);
  t0 = millis() + 1000;
  struct AES_ctx ctx;
  // Since we know the block is a multiple of 16
  // let's skip the checks and make things slightly faster
  while (millis() < t0) {
    AES_init_ctx(&ctx, pKey);
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf));
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 16));
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 32));
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 48));
    // encrypts in place, 16 bytes at a time
    counter++;
  }
  // Since it encrypts in place, the result now has nothing to do with the original.
  // Let's do it again once.
  memcpy(encBuf, aPlaintextECB, 64);
  AES_init_ctx(&ctx, pKey);
  AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf));
  AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 16));
  AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 32));
  AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + 48));
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, 64);
  Serial.printf("%d round / s\n", counter);
  if (memcmp(encBuf, aEncryptedtextECB128, 64) == 0) {
    Serial.println("[o] Pass");
  } else {
    Serial.println("[XXXX] Big Fail!");
  }
  memcpy(decBuf, encBuf, 64);

  t0 = millis() + 1000;
  counter = 0;
  while (millis() < t0) {
    AES_init_ctx(&ctx, pKey);
    AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf));
    AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 16));
    AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 32));
    AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 48));
    // decrypts in place, 16 bytes at a time
    counter++;
  }
  memcpy(decBuf, encBuf, 64);
  AES_init_ctx(&ctx, pKey);
  AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf));
  AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 16));
  AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 32));
  AES_ECB_decrypt(&ctx, (uint8_t*)(decBuf + 48));
  // decrypts in place, 16 bytes at a time
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)decBuf, 64);
  Serial.printf("%d round / s\n", counter);
  if (memcmp(decBuf, aPlaintextECB, 64)) {
    Serial.println("[o] Pass");
  } else {
    Serial.println("[XXXX] Big Fail!");
  }

  Serial.println("IV:");
  hexDump(Iv, 16);
  memcpy(plainBuf, aPlaintextCBC, 64);
  counter = 0;
  t0 = millis() + 1000;
  while (millis() < t0) {
    encryptCBC((uint8_t*)plainBuf, 64, Iv);
    counter++;
  }
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, 64);
  Serial.printf("%d round / s\n", counter);
  if (memcmp(encBuf, aEncryptedtextCBC128, 64)) {
    Serial.println("[o] Pass");
  } else {
    Serial.println("[XXXX] Big Fail!");
  }
  memcpy(decBuf, encBuf, 64);
  counter = 0;
  t0 = millis() + 1000;
  while (millis() < t0) {
    decryptCBC((uint8_t*)encBuf, 64, Iv);
    counter++;
  }
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, 64);
  Serial.printf("%d round / s\n", counter);
  if (memcmp(encBuf, aPlaintextCBC, 64)) {
    Serial.println("[o] Pass");
  } else {
    Serial.println("[XXXX] Big Fail!");
  }
}

void loop() {
}

int16_t decryptECB(uint8_t* myBuf, uint8_t olen) {
  uint8_t reqLen = 16;
  if (olen < reqLen) return -1;
  uint8_t len;
  // or just copy over
  memcpy(encBuf, myBuf, olen);
  len = olen;
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, pKey);
  uint8_t rounds = len / 16, steps = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    // void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    AES_ECB_decrypt(&ctx, (uint8_t*)encBuf + steps);
    steps += 16;
    // decrypts in place, 16 bytes at a time
  }
  return len;
}

uint16_t encryptECB(uint8_t* myBuf, uint8_t len) {
  // first ascertain length
  uint16_t olen;
  struct AES_ctx ctx;
  olen = len;
  if (olen != 16) {
    if (olen % 16 > 0) {
      if (olen < 16) olen = 16;
      else olen += 16 - (olen % 16);
    }
  }
  if (olen != len) memset(encBuf, (olen - len), olen);
  memcpy(encBuf, myBuf, len);
  // encBuf[len] = 0;
  AES_init_ctx(&ctx, pKey);
  uint8_t rounds = olen / 16, steps = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + steps));
    steps += 16;
    // encrypts in place, 16 bytes at a time
  }
  return olen;
}

int16_t encryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  memset(encBuf, (length - olen), length);
  memcpy(encBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encBuf, length);
  return length;
}

int16_t decryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  // We *could* trust the user with the buffer length, but...
  // Let's just make sure eh?
  memcpy(decBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t*)decBuf, length);
  return length;
}
