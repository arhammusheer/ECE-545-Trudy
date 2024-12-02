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
    IDLE,          // Waiting for DH parameters
    RECEIVED_PG,   // Received DH parameters from Alice
    SENT_PG,       // Sent DH parameters to Bob
    RECEIVED_ACK,  // Received ACK from Bob
    SENT_ACK,      // Sent ACK to Alice
    RECEIVED_AKEY, // Received Alice's public key
    SENT_TBKEY,    // Sent Trudy's public key to Bob
    RECEIVED_BKEY, // Received Bob's public key
    SENT_TAKEY,     // Sent Trudy's public key to Alice
};

SecurityLevel securityLevel = LEVEL0; // Current security level
Level1State level1State = IDLE;       // Current state in level 1

long AliceSideKey = 0; // Alice's public key
long BobSideKey = 0;   // Bob's public key

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
    Serial.begin(9600);  // For debugging, if needed
    Serial3.begin(9600); // Alice
    Serial4.begin(9600); // Bob
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

// Check if Alice sent Diffie-Hellman parameters
void checkDHPG(String message)
{
    // If not a DH message, return
    if (message.startsWith("PG") == false)
    {
        return;
    }

    // Set the security level to 1
    securityLevel = LEVEL1;

    level1State = RECEIVED_PG;

    // Extract the parameters from the message
    int comma = message.indexOf(',');
    int p = message.substring(3, comma).toInt();
    int g = message.substring(comma + 1).toInt();

    // Send the parameters to Bob
    send(Serial4, message);
    level1State = SENT_PG;

    // Wait for Bob's ACK
    while (level1State != RECEIVED_ACK)
    {
        String message = readSerial(Serial4);
        if (message.startsWith("ACK"))
        {
            level1State = RECEIVED_ACK;
        }
    }

    // Send ACK to Alice
    send(Serial3, "ACK\n");

    level1State = SENT_ACK;

    // Generate a random private key
    int t = random(1, p - 1);
    long T = modExp(g, a, p);
    


    // Wait for Alice's public key
    long AKey;
    while (level1State != RECEIVED_AKEY)
    {
        String message = readSerial(Serial3);
        if (message.startsWith("AKEY"))
        {
            level1State = RECEIVED_AKEY;
            //AKEY:128
            AKey = message.substring(5).toInt();
        }
    }

    // Send Trudy's public key to Bob
    send(Serial4, "AKEY:" + String(T) + "\n");

    level1State = SENT_TBKEY;

    // Wait for Bob's public key
    long BKey;
    while (level1State != RECEIVED_BKEY)
    {
        String message = readSerial(Serial4);
        if (message.startsWith("BKEY"))
        {
            level1State = RECEIVED_BKEY;
            //BKEY:128
            BKey = message.substring(5).toInt();
        }
    }

    // Send Trudy's public key to Alice
    send(Serial3, "BKEY:" + String(T) + "\n");

    // Calculate the shared secrets with Alice and Bob
    long AliceSharedSecret = modExp(BKey, t, p);
    long BobSharedSecret = modExp(AKey, t, p);

    // Print the shared secrets
    Serial.print("Alice's shared secret: ");
    Serial.println(AliceSharedSecret);
    Serial.print("Bob's shared secret: ");
    Serial.println(BobSharedSecret);
}

void relay(HardwareSerial &from, HardwareSerial &to, String debug_label)
{
    String message = readSerial(from);
    if (message != "")
    {
        Serial.print(debug_label);
        Serial.print(message);
        send(to, message);
    }
}

String encrypt(String message, long key)
{
    String encryptedText = "";
    for (size_t i = 0; i < message.length(); i++)
    {
        char encryptedChar = message[i] ^ (key % 256);
        encryptedText += String((int)encryptedChar) + " ";  // Store ASCII values
    }
    return encryptedText;
}


String decrypt(String message, long key)
{
    String decryptedText = "";
    int i = 0;
    while (i < message.length())
    {
        int ascii = message.substring(i, message.indexOf(' ', i)).toInt();
        char decryptedChar = ascii ^ (key % 256);
        decryptedText += decryptedChar;
        i = message.indexOf(' ', i) + 1;
    }
    return decryptedText;
}


void loop()
{
    if (securityLevel == LEVEL0)
    {
        // Check for DH init
        checkDHPG(readSerial(Alice));

        // Basic Relay
        relay(Alice, Bob, "A->B: ");
        relay(Bob, Alice, "B->A: ");
    }
    else if (securityLevel == LEVEL1)
    {
        // Encrypted Relay
        String message = readSerial(Alice);
        if (message != "")
        {
            Serial.print("A->B: ");
            // Decrypt the message
            message = decrypt(message, AliceSharedSecret);
            Serial.println(message);
            send(Bob, encrypt(message, BobSharedSecret));
        }

        message = readSerial(Bob);
        if (message != "")
        {
            Serial.print("B->A: ");
            // Decrypt the message
            message = decrypt(message, BobSharedSecret);
            Serial.println(message);
            send(Alice, encrypt(message, AliceSharedSecret));
        }
    }
    else if (securityLevel == LEVEL2)
    {
        // Do nothing
    }
}
