// MITM Demo Code for Teensy 4.0

#define Alice Serial3
#define Bob Serial4

enum SecurityLevel
{
    LEVEL0,
    LEVEL1,
    LEVEL2
};

enum Level1State
{
    IDLE,
    RECEIVED_PG_AKEY,
    RECEIVED_PG_BKEY,
    CONNECTED
};

SecurityLevel securityLevel = LEVEL0; // Current security level
Level1State level1State = IDLE;       // Current state in level 1

long AliceSharedSecret = 0; // Alice's public key
long BobSharedSecret = 0;   // Bob's public key

long TrudyPrivateKey = 0; // Trudy's private key
long TrudyPublicKey = 0;  // Trudy's public key

// Utility function for modular exponentiation
long modExp(long base, long exponent, long modulus)
{
    long result = 1;
    base = base % modulus;
    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        { // If exponent is odd
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1; // exponent = exponent / 2
        base = (base * base) % modulus;
    }
    return result;
}

void setup()
{
    Serial.begin(9600); // For debugging, if needed
    Alice.begin(9600);  // Serial port to Alice
    Bob.begin(9600);    // Serial port to Bob
}

// Function to read messages from a serial port
String readSerial(HardwareSerial &serial)
{
    static String buffer3 = "";
    static String buffer4 = "";
    String *buffer;

    // Select the appropriate buffer based on the serial port
    if (&serial == &Serial3)
    {
        buffer = &buffer3;
    }
    else if (&serial == &Serial4)
    {
        buffer = &buffer4;
    }
    else
    {
        return "";
    }

    // Read incoming data and build the message
    while (serial.available())
    {
        char c = serial.read();
        *buffer += c;
        if (c == '\n')
        {
            String message = *buffer;
            *buffer = "";
            return message;
        }
    }
    return "";
}

// Function to send a message through a serial port
void send(HardwareSerial &serial, const String &message)
{
    serial.print(message);
}

// Function to check if the received message is a DH public key
void checkDHPG(const String &message)
{
    if (message.startsWith("PG_AKEY:"))
    {
        // PG_AKEY:2089,2,1019
        Serial.print("A->T: ");
        Serial.print(message);

        // Extract P, G, and A values
        int start = message.indexOf(':') + 1; // Start after "PG_AKEY:"
        int firstComma = message.indexOf(',', start);
        int secondComma = message.indexOf(',', firstComma + 1);

        long p = message.substring(start, firstComma).toInt();
        long g = message.substring(firstComma + 1, secondComma).toInt();
        long A = message.substring(secondComma + 1).toInt();

        // Generate a private key
        TrudyPrivateKey = random(2, p - 1);
        TrudyPublicKey = modExp(g, TrudyPrivateKey, p);

        // Calculate the shared secret
        // A^t mod p
        AliceSharedSecret = modExp(A, TrudyPrivateKey, p);

        // Send the public key to Alice
        send(Alice, "PG_BKEY:" + String(p) + "," + String(g) + "," + String(TrudyPublicKey) + "\n");
        Serial.print("T->A: ");
        Serial.println("PG_BKEY:" + String(p) + "," + String(g) + "," + String(TrudyPublicKey));

        // Now work on Bob
        send(Bob, "PG_AKEY:" + String(p) + "," + String(g) + "," + String(TrudyPublicKey) + "\n");
        Serial.print("T->B: ");
        Serial.println("PG_AKEY:" + String(p) + "," + String(g) + "," + String(TrudyPublicKey));

        // Wait for Bob's Response
        while (true)
        {
            String message = readSerial(Bob);
            if (message.startsWith("PG_BKEY:"))
            {
                // Extract P, G, and A values
                int start = message.indexOf(':') + 1; // Start after "PG_AKEY:"
                int firstComma = message.indexOf(',', start);
                int secondComma = message.indexOf(',', firstComma + 1);

                long p = message.substring(start, firstComma).toInt();
                long _ = message.substring(firstComma + 1, secondComma).toInt();
                long B = message.substring(secondComma + 1).toInt();

                Serial.print("B->T: ");
                Serial.print(message);

                // Calculate the shared secret
                // B^t mod p
                BobSharedSecret = modExp(B, TrudyPrivateKey, p);
                break;
            }
        }

        securityLevel = LEVEL1;

        // Debugging
        Serial.print("Alice Shared Secret: ");
        Serial.println(AliceSharedSecret);
        Serial.print("Bob Shared Secret: ");
        Serial.println(BobSharedSecret);
    }
}
String encrypt(String plainText, int key)
{
    // Use % 256 for compatibility with Teensy's key derivation
    int derivedKey = key % 256;
    String encryptedText = "";
    for (int i = 0; i < plainText.length(); i++)
    {
        char plainChar = plainText.charAt(i);
        char encryptedChar = plainChar ^ derivedKey;
        encryptedText += String((int)encryptedChar); // Convert to ASCII-like integer
        encryptedText += " ";                        // Add space as delimiter
    }
    return encryptedText; // Ensure no trailing space
}

String decrypt(String cipherText, int key)
{
    // Use % 256 for compatibility with Teensy's key derivation
    int derivedKey = key % 256;
    String decryptedText = "";
    int i = 0;
    while (i < cipherText.length())
    {
        int spaceIndex = cipherText.indexOf(' ', i);
        if (spaceIndex == -1)
        {
            break;
        }
        String cipherChar = cipherText.substring(i, spaceIndex);
        char encryptedChar = (char)cipherChar.toInt(); // Convert back from ASCII-like integer
        char decryptedChar = encryptedChar ^ derivedKey;
        decryptedText += decryptedChar;
        i = spaceIndex + 1;
    }
    return decryptedText;
}
void loop()
{
    String message = "";
    if (securityLevel == LEVEL0)
    {
        // Check for DH init
        message = readSerial(Alice);
        if (message != "")
        {
            Serial.print("A->B: ");
            Serial.print(message);
            send(Bob, message);

            checkDHPG(message);
        }

        message = readSerial(Bob);
        if (message != "")
        {
            Serial.print("B->A: ");
            Serial.print(message);
            send(Alice, message);
        }
    }
    else if (securityLevel == LEVEL1)
    {
        // Encrypted Relay
        String message = readSerial(Alice);
        if (message != "")
        {
            // Decrypt the message
            message = decrypt(message, AliceSharedSecret);
            Serial.print("A->T->B: ");
            Serial.println(message);

            message = encrypt(message, BobSharedSecret);
            send(Bob, message);
        }

        message = readSerial(Bob);
        if (message != "")
        {

            // Decrypt the message
            message = decrypt(message, BobSharedSecret);
            Serial.print("B->T->A: ");
            Serial.println(message);

            message = encrypt(message, AliceSharedSecret);
            send(Alice, message);
        }
    }
}
