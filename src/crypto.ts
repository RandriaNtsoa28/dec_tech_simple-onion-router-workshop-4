import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // TODO implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

  // Generate RSA key pair
  const keys = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: { name: "SHA-256" },
      },
      true,
      ["encrypt", "decrypt"]
  );

  return { publicKey: keys.publicKey, privateKey: keys.privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  // Convert the ArrayBuffer to base64 string
  const base64Key = arrayBufferToBase64(exportedKey);
  return base64Key;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // If the key is null, return null
  if (!key) return null;
  // Export the private key
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  // Convert the ArrayBuffer to base64 string
  const base64Key = arrayBufferToBase64(exportedKey);
  return base64Key;
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBufferKey = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
      "spki",
      arrayBufferKey,
      {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" },
      },
      true,
      ["encrypt"]
  );
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBufferKey = base64ToArrayBuffer(strKey);
  // Import the private key from the ArrayBuffer
  const importedKey = await webcrypto.subtle.importKey(
      "pkcs8",
      arrayBufferKey,
      {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" },
      },
      true,
      ["decrypt"]
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function
  // Convert the base64-encoded message to an ArrayBuffer
  const data = base64ToArrayBuffer(b64Data);
  // Import the public key from the base64 string
  const publicKey = await importPubKey(strPublicKey);
  // Encrypt the data with the public key
  const encryptedData = await webcrypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publicKey,
      data
  );
  // Convert the encrypted data to a base64 string
  const base64EncryptedData = arrayBufferToBase64(encryptedData);
  return base64EncryptedData;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function
  // Convert the base64-encoded encrypted data to an ArrayBuffer
  const encryptedData = base64ToArrayBuffer(data);

  // Decrypt the data with the private key
  const decryptedData = await webcrypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      encryptedData
  );

  // Convert the decrypted data from an ArrayBuffer to a string
  const decryptedString = arrayBufferToBase64(decryptedData);

  return decryptedString;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // TODO implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.
  try {
    // Generate a random 256-bit (32 bytes) key
    const key = await crypto.subtle.generateKey(
        {
          name: "AES-CBC",
          length: 256 // Use 256 bits key size for AES
        },
        true, // Make the key extractable
        ["encrypt", "decrypt"] // Key can be used for both encryption and decryption
    );

    return key;
  } catch (error) {
    console.error("Error creating random symmetric key:", error);
    throw error;
  }

}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key
  try {
    // Export the symmetric key
    const exportedKey = await crypto.subtle.exportKey("raw", key);

    // Convert the exported key data to a Base64 string
    const exportedBase64 = arrayBufferToBase64(exportedKey);

    return exportedBase64;
  } catch (error) {
    console.error("Error exporting symmetric key:", error);
    throw error;
  }
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object
  try {
    // Convert the Base64 string to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(strKey);

    // Import the ArrayBuffer as a CryptoKey
    const symmetricKey = await crypto.subtle.importKey(
        "raw",
        arrayBuffer,
        {
          name: "AES-CBC"
        },
        true, // Make the key extractable
        ["encrypt", "decrypt"] // Key can be used for both encryption and decryption
    );

    return symmetricKey;
  } catch (error) {
    console.error("Error importing symmetric key:", error);
    throw error;
  }

}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder
  try {
    // Generate a random initialization vector (IV)
    const iv = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes for AES-CBC IV

    // Convert the string data to a Uint8Array using TextEncoder
    const encodedData = new TextEncoder().encode(data);

    // Encrypt the data with the symmetric key and the generated IV
    const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-CBC",
          iv: iv, // Include the IV in the encryption parameters
        },
        key,
        encodedData
    );

    // Combine the IV and the encrypted data into a single buffer
    const combinedBuffer = new Uint8Array(iv.length + encryptedData.byteLength);
    combinedBuffer.set(iv);
    combinedBuffer.set(new Uint8Array(encryptedData), iv.length);

    // Convert the combined buffer to a Base64 string
    const encryptedBase64 = arrayBufferToBase64(combinedBuffer.buffer);

    return encryptedBase64;
  } catch (error) {
    console.error("Error encrypting message:", error);
    throw error;
  }

}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format
  try {
    // Import the symmetric key from Base64 string to CryptoKey
    const symmetricKey = await importSymKey(strKey);

    // Decode the Base64 encrypted data to ArrayBuffer
    const arrayBuffer = base64ToArrayBuffer(encryptedData);

    // Extract the IV (first 16 bytes) from the combined buffer
    const iv = arrayBuffer.slice(0, 16);

    // Extract the encrypted data (after the IV) from the combined buffer
    const encryptedBytes = arrayBuffer.slice(16);

    // Decrypt the data with the symmetric key and the extracted IV
    const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-CBC",
          iv: iv, // Include the IV in the decryption parameters
        },
        symmetricKey,
        encryptedBytes
    );

    // Convert the decrypted data ArrayBuffer to a string using TextDecoder
    const decryptedString = new TextDecoder().decode(decryptedData);

    return decryptedString;
  } catch (error) {
    console.error("Error decrypting message:", error);
    throw error;
  }

}
