public class AES {
    private static final int AES_BLOCK_SIZE = 16;
    private static final int AES_KEY_SIZE = 16;
    private static final int NUMBER_OF_ROUNDS = 10;

    private static final int[][] SBOX = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    private static final int[][] INV_SBOX = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    private static final int[] RCON = {
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x1B, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00
    };

    private static int[][] expandKey(byte[] key) {
        int[][] expandedKey = new int[4][AES_BLOCK_SIZE * (NUMBER_OF_ROUNDS + 1)];

        // Copy the original key to the first columns of the expanded key
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            expandedKey[i % 4][i] = key[i];
        }

        int bytesGenerated = AES_KEY_SIZE;
        int rconIteration = 1;
        byte[] temp = new byte[4];

        while (bytesGenerated < AES_BLOCK_SIZE * (NUMBER_OF_ROUNDS + 1)) {
            for (int i = 0; i < 4; i++) {
                temp[i] = (byte) expandedKey[i][bytesGenerated - 1];
            }

            if (bytesGenerated % AES_KEY_SIZE == 0) {
                temp = rotateWord(temp);
                temp = substituteBytes(temp);

                temp[0] ^= RCON[rconIteration];
                rconIteration++;
            } else if (AES_KEY_SIZE > 6 && bytesGenerated % AES_KEY_SIZE == 4) {
                temp = substituteBytes(temp);
            }

            for (int i = 0; i < 4; i++) {
                expandedKey[i][bytesGenerated] = expandedKey[i][bytesGenerated - AES_KEY_SIZE] ^ temp[i];
            }

            bytesGenerated++;
        }

        return expandedKey;
    }

    private static byte[] rotateWord(byte[] word) {
        byte temp = word[0];

        for (int i = 0; i < 3; i++) {
            word[i] = word[i + 1];
        }

        word[3] = temp;

        return word;
    }

    private static byte[] substituteBytes(byte[] word) {
        for (int i = 0; i < 4; i++) {
            int row = (word[i] & 0xF0) >>> 4;
            int col = word[i] & 0x0F;
            word[i] = (byte) SBOX[row][col];
        }

        return word;
    }

    private static byte[][] addRoundKey(byte[][] state, int[][] roundKey, int round) {
        for (int c = 0; c < AES_BLOCK_SIZE; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] ^= roundKey[r][round * AES_BLOCK_SIZE + c];
            }
        }

        return state;
    }

    private static byte[][] substituteBytes(byte[][] state) {
        for (int c = 0; c < AES_BLOCK_SIZE; c++) {
            int row = (state[0][c] & 0xF0) >>> 4;
            int col = state[0][c] & 0x0F;
            state[0][c] = (byte) SBOX[row][col];

            row = (state[1][c] & 0xF0) >>> 4;
            col = state[1][c] & 0x0F;
            state[1][c] = (byte) SBOX[row][col];

            row = (state[2][c] & 0xF0) >>> 4;
            col = state[2][c] & 0x0F;
            state[2][c] = (byte) SBOX[row][col];

            row = (state[3][c] & 0xF0) >>> 4;
            col = state[3][c] & 0x0F;
            state[3][c] = (byte) SBOX[row][col];
        }

        return state;
    }

    private static byte[][] inverseSubstituteBytes(byte[][] state) {
        for (int c = 0; c < AES_BLOCK_SIZE; c++) {
            int row = (state[0][c] & 0xF0) >>> 4;
            int col = state[0][c] & 0x0F;
            state[0][c] = (byte) INV_SBOX[row][col];

            row = (state[1][c] & 0xF0) >>> 4;
            col = state[1][c] & 0x0F;
            state[1][c] = (byte) INV_SBOX[row][col];

            row = (state[2][c] & 0xF0) >>> 4;
            col = state[2][c] & 0x0F;
            state[2][c] = (byte) INV_SBOX[row][col];

            row = (state[3][c] & 0xF0) >>> 4;
            col = state[3][c] & 0x0F;
            state[3][c] = (byte) INV_SBOX[row][col];
        }

        return state;
    }

    private static byte[][] shiftRows(byte[][] state) {
        byte temp;

        // Row 1
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // Row 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3
        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;

        return state;
    }

    private static byte[][] inverseShiftRows(byte[][] state) {
        byte temp;

        // Row 1
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Row 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;

        return state;
    }

    private static byte[][] mixColumns(byte[][] state) {
        byte[] col = new byte[4];

        for (int c = 0; c < AES_BLOCK_SIZE; c++) {
            for (int i = 0; i < 4; i++) {
                col[i] = state[i][c];
            }

            col = mixColumn(col);

            for (int i = 0; i < 4; i++) {
                state[i][c] = col[i];
            }
        }

        return state;
    }

    private static byte[][] inverseMixColumns(byte[][] state) {
        byte[] col = new byte[4];

        for (int c = 0; c < AES_BLOCK_SIZE; c++) {
            for (int i = 0; i < 4; i++) {
                col[i] = state[i][c];
            }

            col = inverseMixColumn(col);

            for (int i = 0; i < 4; i++) {
                state[i][c] = col[i];
            }
        }

        return state;
    }

    private static byte[] mixColumn(byte[] col) {
        byte[] mixedCol = new byte[4];

        mixedCol[0] = (byte) (mul2(col[0]) ^ mul3(col[1]) ^ col[2] ^ col[3]);
        mixedCol[1] = (byte) (col[0] ^ mul2(col[1]) ^ mul3(col[2]) ^ col[3]);
        mixedCol[2] = (byte) (col[0] ^ col[1] ^ mul2(col[2]) ^ mul3(col[3]));
        mixedCol[3] = (byte) (mul3(col[0]) ^ col[1] ^ col[2] ^ mul2(col[3]));

        return mixedCol;
    }

    private static byte[] inverseMixColumn(byte[] col) {
        byte[] mixedCol = new byte[4];

        mixedCol[0] = (byte) (mul14(col[0]) ^ mul11(col[1]) ^ mul13(col[2]) ^ mul9(col[3]));
        mixedCol[1] = (byte) (mul9(col[0]) ^ mul14(col[1]) ^ mul11(col[2]) ^ mul13(col[3]));
        mixedCol[2] = (byte) (mul13(col[0]) ^ mul9(col[1]) ^ mul14(col[2]) ^ mul11(col[3]));
        mixedCol[3] = (byte) (mul11(col[0]) ^ mul13(col[1]) ^ mul9(col[2]) ^ mul14(col[3]));

        return mixedCol;
    }

    private static int mul2(int value) {
        int result = value << 1;

        if ((result & 0x100) != 0) {
            result ^= 0x1B;
        }

        return result & 0xFF;
    }

    private static int mul3(int value) {
        return mul2(value) ^ value;
    }

    private static int mul9(int value) {
        return mul2(mul2(mul2(value))) ^ value;
    }

    private static int mul11(int value) {
        return mul2(mul2(mul2(value)) ^ value) ^ value;
    }

    private static int mul13(int value) {
        return mul2(mul2(mul2(value) ^ value)) ^ value;
    }

    private static int mul14(int value) {
        return mul2(mul2(mul2(value) ^ value) ^ value);
    }

    private static byte[][] encryptBlock(byte[][] block, int[][] roundKey) {
        byte[][] state = addRoundKey(block, roundKey, 0);

        for (int round = 1; round < NUMBER_OF_ROUNDS; round++) {
            state = substituteBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, roundKey, round);
        }

        state = substituteBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKey, NUMBER_OF_ROUNDS);

        return state;
    }

    private static byte[][] decryptBlock(byte[][] block, int[][] roundKey) {
        byte[][] state = addRoundKey(block, roundKey, NUMBER_OF_ROUNDS);

        for (int round = NUMBER_OF_ROUNDS - 1; round >= 1; round--) {
            state = inverseShiftRows(state);
            state = inverseSubstituteBytes(state);
            state = addRoundKey(state, roundKey, round);
            state = inverseMixColumns(state);
        }

        state = inverseShiftRows(state);
        state = inverseSubstituteBytes(state);
        state = addRoundKey(state, roundKey, 0);

        return state;
    }

    private static byte[] padMessage(byte[] message) {
        int paddingSize = AES_BLOCK_SIZE - (message.length % AES_BLOCK_SIZE);
        byte[] paddedMessage = new byte[message.length + paddingSize];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);

        for (int i = 0; i < paddingSize; i++) {
            paddedMessage[message.length + i] = (byte) paddingSize;
        }

        return paddedMessage;
    }

    private static byte[] unpadMessage(byte[] paddedMessage) {
        int paddingSize = paddedMessage[paddedMessage.length - 1];
        byte[] message = new byte[paddedMessage.length - paddingSize];
        System.arraycopy(paddedMessage, 0, message, 0, message.length);

        return message;
    }

    public static byte[] encrypt(byte[] message, byte[] key) {
        byte[] paddedMessage = padMessage(message);
        int[][] roundKey = expandKey(key);
        byte[] ciphertext = new byte[paddedMessage.length];

        for (int i = 0; i < paddedMessage.length; i += AES_BLOCK_SIZE) {
            byte[][] block = new byte[4][AES_BLOCK_SIZE];

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j / 4][j % 4] = paddedMessage[i + j];
            }

            byte[][] encryptedBlock = encryptBlock(block, roundKey);

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                ciphertext[i + j] = encryptedBlock[j / 4][j % 4];
            }
        }

        return ciphertext;
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        int[][] roundKey = expandKey(key);
        byte[] plaintext = new byte[ciphertext.length];

        for (int i = 0; i < ciphertext.length; i += AES_BLOCK_SIZE) {
            byte[][] block = new byte[4][AES_BLOCK_SIZE];

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j / 4][j % 4] = ciphertext[i + j];
            }

            byte[][] decryptedBlock = decryptBlock(block, roundKey);

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                plaintext[i + j] = decryptedBlock[j / 4][j % 4];
            }
        }

        byte[] unpaddedPlaintext = unpadMessage(plaintext);
        return unpaddedPlaintext;
    }

    public static void main(String[] args) {
        // Вхідні дані
        byte[] key = "0123456789abcdef".getBytes(); // 128-бітний ключ (16 байт)
        byte[] message = "The most secret info".getBytes(); // Повідомлення для шифрування

        // Шифрування
        byte[] encrypted = encrypt(message, key);
        System.out.println("Шифрований текст: " + bytesToHex(encrypted));

        // Дешифрування
        byte[] decrypted = decrypt(encrypted, key);
        System.out.println("Розшифрований текст: " + new String(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}