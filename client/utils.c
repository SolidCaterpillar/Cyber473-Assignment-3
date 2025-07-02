#include "malware.h"

// XOR encryption/decryption with optional key rotation
void XORCrypt(char* data, size_t len, char* key, BOOL shift) {
    unsigned char* ukey = (unsigned char*)key;  // Cast to unsigned for bit operations
    
    // Process each byte in the data buffer
    for (size_t i = 0; i < len; i++) {
        // XOR with current key byte
        data[i] ^= *ukey;
        
        // Rotate key if requested
        if (shift) {
            // Right shift 1 bit with left wrap-around
            *ukey = (*ukey >> 1) | ((*ukey & 1) << 7);
        }
    }
}