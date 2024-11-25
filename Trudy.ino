#include <Arduino.h>

// Communication parameters
long sharedSecretWithAlice = 0;  // Shared secret with Alice
long sharedSecretWithBob = 0;    // Shared secret with Bob
long p, g, alicePublicKey, bobPublicKey;  // DH parameters and public keys
bool isEncrypted = false;        // Encryption enabled/disabled flag
bool ackReceivedFromBob = false;
bool keyExchangeComplete = false;

String messageFromAlice = "";   // Buffer for Alice's message
String messageFromBob = "";     // Buffer for Bob's message

// Communication levels
enum CommunicationLevel {
  LEVEL0,
  LEVEL1
};

CommunicationLevel communicationLevel = LEVEL0;

// Utility for modular exponentiation
long modularExponentiation(long base, int exp, long mod) {
  long result = 1;
  base = base % mod;
  while (exp > 0) {
    if (exp % 2 == 1)
      result = (result * base) % mod;
    exp = exp >> 1;
    base = (base * base) % mod;
  }
  return result;
}

// Encrypt message using XOR and shared secret
String encryptMessage(String message, long sharedSecret) {
  String encryptedMessage = "";
  for (char c : message) {
    encryptedMessage += String((int)(c ^ (sharedSecret % 256))) + " ";
  }
  return encryptedMessage.trim();
}

// Decrypt message using XOR and shared secret
String decryptMessage(String message, long sharedSecret) {
  String decryptedMessage = "";
  char *msg = &message[0];
  char *token = strtok(msg, " ");
  while (token != NULL) {
    int value = atoi(token);
    decryptedMessage += (char)(value ^ (sharedSecret % 256));
    token = strtok(NULL, " ");
  }
  return decryptedMessage;
}

void setup() {
  Serial.begin(9600);     // Serial monitor
  Serial3.begin(9600);    // Alice on Serial3
  Serial4.begin(9600);    // Bob on Serial4
}

void loop() {
  if (communicationLevel == LEVEL0) {
    checkForPgMessage();
    relayPlainTextMessages();
  } else if (communicationLevel == LEVEL1) {
    if (!keyExchangeComplete) {
      interceptKeyExchange();
    } else {
      relayEncryptedMessages();
    }
  }
}

// Relay plain-text messages directly
void relayPlainTextMessages() {
  // From Alice to Bob
  while (Serial3.available()) {
    char incomingChar = Serial3.read();
    messageFromAlice += incomingChar;

    if (incomingChar == '\n') {
      // Relay the message as-is
      Serial4.print(messageFromAlice);
      Serial.print("Alice to Bob (plain text): ");
      Serial.print(messageFromAlice);
      messageFromAlice = ""; // Clear buffer
    }
  }

  // From Bob to Alice
  while (Serial4.available()) {
    char incomingChar = Serial4.read();
    messageFromBob += incomingChar;

    if (incomingChar == '\n') {
      // Relay the message as-is
      Serial3.print(messageFromBob);
      Serial.print("Bob to Alice (plain text): ");
      Serial.print(messageFromBob);
      messageFromBob = ""; // Clear buffer
    }
  }
}

// Detect and process PG messages for Diffie-Hellman setup
void checkForPgMessage() {
  while (Serial3.available()) {
    char incomingChar = Serial3.read();
    messageFromAlice += incomingChar;

    if (incomingChar == '\n') {
      if (messageFromAlice.startsWith("PG:")) {
        // Detected PG message, upgrade to Level 1
        communicationLevel = LEVEL1;
        isEncrypted = true;

        // Extract p and g
        int commaIndex = messageFromAlice.indexOf(',');
        p = messageFromAlice.substring(3, commaIndex).toInt();
        g = messageFromAlice.substring(commaIndex + 1).toInt();

        Serial.print("Intercepted PG from Alice: p=");
        Serial.print(p);
        Serial.print(", g=");
        Serial.println(g);

        // Forward PG to Bob
        Serial4.print(messageFromAlice);

        // Initialize key exchange variables
        ackReceivedFromBob = false;
        keyExchangeComplete = false;

      } else {
        // Relay the message as-is
        Serial4.print(messageFromAlice);
        Serial.print("Alice to Bob (plain text): ");
        Serial.print(messageFromAlice);
      }
      messageFromAlice = ""; // Clear buffer
    }
  }
}

// Intercept key exchange for Diffie-Hellman
void interceptKeyExchange() {
  // From Bob to Trudy
  if (!ackReceivedFromBob && Serial4.available()) {
    String bobMessage = Serial4.readStringUntil('\n');
    if (bobMessage == "ACK") {
      ackReceivedFromBob = true;
      Serial.print("Received ACK from Bob\n");
      // Forward ACK to Alice
      Serial3.println("ACK");
    }
  }

  // Intercept AKEY from Alice
  if (ackReceivedFromBob && !keyExchangeComplete && Serial3.available()) {
    String aliceMessage = Serial3.readStringUntil('\n');
    if (aliceMessage.startsWith("AKEY:")) {
      alicePublicKey = aliceMessage.substring(5).toInt();
      Serial.print("Intercepted AKEY from Alice: ");
      Serial.println(alicePublicKey);

      // Trudy's private key for Alice
      int trudyPrivateKeyAlice = 19;
      long fakeBKey = modularExponentiation(g, trudyPrivateKeyAlice, p);
      sharedSecretWithAlice = modularExponentiation(alicePublicKey, trudyPrivateKeyAlice, p);

      // Send fake BKEY to Alice
      Serial3.println("BKEY:" + String(fakeBKey));
      Serial.print("Sent fake BKEY to Alice: ");
      Serial.println(fakeBKey);
    }
  }

  // Intercept BKEY from Bob
  if (ackReceivedFromBob && !keyExchangeComplete && Serial4.available()) {
    String bobMessage = Serial4.readStringUntil('\n');
    if (bobMessage.startsWith("BKEY:")) {
      bobPublicKey = bobMessage.substring(5).toInt();
      Serial.print("Intercepted BKEY from Bob: ");
      Serial.println(bobPublicKey);

      // Trudy's private key for Bob
      int trudyPrivateKeyBob = 17;
      long fakeAKey = modularExponentiation(g, trudyPrivateKeyBob, p);
      sharedSecretWithBob = modularExponentiation(bobPublicKey, trudyPrivateKeyBob, p);

      // Send fake AKEY to Bob
      Serial4.println("AKEY:" + String(fakeAKey));
      Serial.print("Sent fake AKEY to Bob: ");
      Serial.println(fakeAKey);

      // Key exchange complete
      keyExchangeComplete = true;

      // Log shared secrets
      Serial.print("Shared secret with Alice: ");
      Serial.println(sharedSecretWithAlice);
      Serial.print("Shared secret with Bob: ");
      Serial.println(sharedSecretWithBob);
    }
  }
}

// Relay encrypted messages between Alice and Bob
void relayEncryptedMessages() {
  // From Alice to Bob
  while (Serial3.available()) {
    char incomingChar = Serial3.read();
    messageFromAlice += incomingChar;

    if (incomingChar == '\n') {
      // Decrypt message from Alice
      String decryptedMessage = decryptMessage(messageFromAlice.trim(), sharedSecretWithAlice);
      // Log decrypted message
      Serial.print("Decrypted message from Alice: ");
      Serial.println(decryptedMessage);

      // Re-encrypt message for Bob
      String reEncryptedMessage = encryptMessage(decryptedMessage, sharedSecretWithBob);
      Serial4.println(reEncryptedMessage);
      Serial.print("Forwarded to Bob: ");
      Serial.println(reEncryptedMessage);

      messageFromAlice = ""; // Clear buffer
    }
  }

  // From Bob to Alice
  while (Serial4.available()) {
    char incomingChar = Serial4.read();
    messageFromBob += incomingChar;

    if (incomingChar == '\n') {
      // Decrypt message from Bob
      String decryptedMessage = decryptMessage(messageFromBob.trim(), sharedSecretWithBob);
      // Log decrypted message
      Serial.print("Decrypted message from Bob: ");
      Serial.println(decryptedMessage);

      // Re-encrypt message for Alice
      String reEncryptedMessage = encryptMessage(decryptedMessage, sharedSecretWithAlice);
      Serial3.println(reEncryptedMessage);
      Serial.print("Forwarded to Alice: ");
      Serial.println(reEncryptedMessage);

      messageFromBob = ""; // Clear buffer
    }
  }
}

