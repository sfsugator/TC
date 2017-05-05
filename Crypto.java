/**
 * Crypto implements the DES, ECB, and CBC encryption algorithms. All functions
 * necessary are included. In a nutshell, DES takes a 64 bit message and a 64
 * bit key and returns an encrypted 64 bit message. ECB handles messages larger
 * than 64 bits by simply breaking the message up into chunks using DES and then
 * concatenating. CBC is the most sophisticated algorithm. It also takes
 * messages greater than 64 bits but uses an initialization value and "chains"
 * the previous block of ciphertext to produce the next chunk. I have included a
 * method called "show(int[] anArray)" which makes it easy to display an array.
 */
package crypto;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.io.UnsupportedEncodingException;

/**
 *
 * @author alfredmuller
 */
public class Crypto {

    //Intial permutation of 64 bit message
    static final int[] initialPermutation = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    //Initial permutation of 64 bit key
    static final int[] keyPerm = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };
    //Per round permutation of left hand side of key
    static final int[] perRoundKeyPermLeft = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2
    };
    //Per round permutation of right hand side of key
    static final int[] perRoundKeyPermRight = {
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32

    };
    //S-boxes used during mangling operation
    static final int[][] s1 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0,
            0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1},
        {0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1,
            1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0},
        {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1,
            0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1}
    };
    static final int[][] s2 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0,
            1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0},
        {0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0,
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1},
        {1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1},
        {1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1}
    };
    static final int[][] s3 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
            0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0},
        {0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1},
        {1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1},
        {1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
            0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0}

    };
    static final int[][] s4 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1},
        {0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1,
            0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1},
        {1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1,
            1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0},
        {1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0,
            1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0}
    };
    static final int[][] s5 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0,
            1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1},
        {0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1,
            0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0,
            1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0},
        {1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1,
            0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1}

    };
    static final int[][] s6 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1},
        {0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1,
            0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0},
        {1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1,
            0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0},
        {1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1}
    };
    static final int[][] s7 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1,
            0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1},
        {0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0,
            1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0},
        {1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0,
            1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0},
        {1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0}
    };
    static final int[][] s8 = {
        {-1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1,
            1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1},
        {0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0},
        {1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0,
            0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0},
        {1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,
            1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1}
    };

    static final int[] finalPermutation = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };
    //s-box permutation
    static final int[] sBoxPerm = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

    /**
     * DES implements the Data Encryption Standard algorithm for encryption of
     * 64 bit messages. If the message or the key is not 64 bits long, an error
     * is printed and the array returned contains -1. DES calls other methods to
     * accomplish the encryption.
     *
     *   ****NOTE**** I have written a show function that will show the returned
     * array. method call is show(int[] array)
     *
     * @param plaintext The message to be encrypted, must be 64 bits long.
     * @param key The key to be used in encryption, must be 64 bits long.
     * @return The encrypted message, ciphertext
     */
    public static int[] DES(int[] plaintext, int[] key) {

        int[] plainArray = new int[64];
        int[] ciphertext = new int[64];
        //Error checks
        if (plaintext.length != 64) {
            System.out.println("Error: The plaintext file must be 64 bits long");
            plainArray[0] = -1;
            return plainArray;
        }
        if (key.length != 64) {
            System.out.println("Error: The key must be 64 bits long");
            plainArray[0] = -1;
            return plainArray;
        }

        int[] initial = initialPermutation(plaintext);
        int[] keyReturn = keyPermutation(key);
        int[] keyUps = getC0(keyReturn);
        int[] keyLow = getD0(keyReturn);
        int[] keyRotated = rotateLeft(keyUps, keyLow, initial);
        ciphertext = finalPermutations(keyRotated);

        return ciphertext;
    }

    /**
     * ECB Implements the Electronic Code Block algorithm of encryption for
     * messages greater than 64 bits long. This method calls DES after breaking
     * up the message into 64 bit blocks. If the last block is less than 64 bits
     * long, it is padded with zeroes at the end of the array. This method takes
     * strings and converts them to ints.
     *
     * @param plaintext A String. The message to be encrypted, must be at least
     * 64 bits long.
     * @param key A String. The key to be used for encryption, must be 64 bits
     * long.
     * @return an encrypted message in the form of an array of integers
     */
    public static int[] ECB(String plaintext, String key) {
        int[] plainArray = new int[64];
        int[] ciphertext = new int[64];
        int[] stringAsBinaryArray = new int[64];
        int[] keyAsBinaryArray = new int[64];
        int messageLength = 0;
        int numArrays = 0;
        //error checks
        if (plaintext.length() < 8) {
            System.out.println("Error: The plaintext file must be at least 64 bits long(8 characters)");
            plainArray[0] = -1;
            return plainArray;
        }
        if (key.length() != 8) {
            System.out.println("Error: The key must be 64 bits long");
            plainArray[0] = -1;
            return plainArray;
        }
        //convert the key string to an array of binary integers
        keyAsBinaryArray = stringToIntegers(key);
        messageLength = plaintext.length();

        //The message is exacctly 64 bits long
        if (messageLength == 8) {
            int[] finalArray = new int[messageLength];
            stringAsBinaryArray = stringToIntegers(plaintext);
            ciphertext = DES(stringAsBinaryArray, keyAsBinaryArray);
            finalArray = binaryArrayToInteger(ciphertext, messageLength);

            return finalArray;
            //The message is longer than 64 bits but needs no padding    
        } else if (messageLength % 8 == 0) {
            int[] concatArray = new int[messageLength * 8];
            int[] finalArray = new int[messageLength];

            for (int i = 0; i < messageLength; i += 8) {
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = DES(stringAsBinaryArray, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, concatArray, i * 8, 64);

            }
            finalArray = binaryArrayToInteger(concatArray, messageLength);

            return finalArray;
            //The message is longer than 64 bits and requires padding
        } else {
            numArrays = messageLength / 8;
            int padding = messageLength % 8;
            int counter = 0;
            int[] concatArrayPad = new int[(messageLength * 8) + ((8 - padding) * 8)];
            int[] finalArray = new int[concatArrayPad.length];

            for (int i = 0; i < messageLength; i += 8) {
                if (counter == numArrays) {
                    stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + padding));
                    for (int j = 0; j < 8 * (8 - padding); j++) {
                        stringAsBinaryArray[padding * 8 + j] = 0;
                    }
                    ciphertext = DES(stringAsBinaryArray, keyAsBinaryArray);
                    System.arraycopy(ciphertext, 0, concatArrayPad, i * 8, 64);
                    finalArray = binaryArrayToInteger(concatArrayPad, messageLength + (8 - padding));

                    return finalArray;
                }
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = DES(stringAsBinaryArray, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, concatArrayPad, i * 8, 64);
                counter++;
            }
        }
        return ciphertext;
    }
    /**
     * CBC uses encrypts a message using the Chain Block Algorithm. The first 64-bit chunk
     * is first XOR'd with an initialization value and then encrypted using DES. The 
     * subsequent blocks of Mi are first XOR'd with Ci-1 then encrypted using DES. In this way
     * identical blocks of messages are not encrypted to the same integers.
     * 
     * @param plaintext The message String must be at least 64 bits long.
     * @param key The key String, must be 64 bits long.
     * @param IV The Initial Value, must be 64 bits long.
     * @return An encrypted message in the form of an integer array.
     */
    public static int[] CBC(String plaintext, String key, String IV) {
        int[] ciphertextError = {0};
        int[] ciphertext = new int[64];
        int[] chainArray = new int[64];
        int[] stringAsBinaryArray = new int[64];
        int[] keyAsBinaryArray = new int[64];
        int[] ivAsBinaryArray = new int[64];
        int messageLength = 0;
        int numArrays = 0;
        //error checks
        if (plaintext.length() < 8) {
            System.out.println("Error: The plaintext file must be at least 64 bits long(8 characters)");
            ciphertextError[0] = -1;
            return ciphertextError;
        }
        if (key.length() != 8) {
            System.out.println("Error: The key must be 64 bits long");
            ciphertextError[0] = -1;
            return ciphertextError;
        }
        if (IV.length() != 8) {
            System.out.println("Error: The IV must be 64 bits long");
            ciphertextError[0] = -1;
            return ciphertextError;
        }
        //convert the key string to an array of binary integers
        keyAsBinaryArray = stringToIntegers(key);
        ivAsBinaryArray = stringToIntegers(IV);
        messageLength = plaintext.length();

        //The message is exacctly 64 bits long
        if (messageLength == 8) {
            int[] finalArray = new int[messageLength];
            stringAsBinaryArray = stringToIntegers(plaintext);
            ciphertext = cbcXOR(stringAsBinaryArray, ivAsBinaryArray);
            ciphertext = DES(ciphertext, keyAsBinaryArray);
            finalArray = binaryArrayToInteger(ciphertext, messageLength);

            return finalArray;
            //The message is longer than 64 bits but needs no padding    
        } else if (messageLength % 8 == 0) {
            int[] concatArray = new int[messageLength * 8];
            int[] finalArray = new int[messageLength];
            //For the first block, XOR m1 with IV, then DES
            for (int i = 0; i < 8; i += 8) {
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = cbcXOR(stringAsBinaryArray, ivAsBinaryArray);
                ciphertext = DES(ciphertext, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, chainArray, 0, 64);
                System.arraycopy(ciphertext, 0, concatArray, 0, 64);

            }
            //For consecutive blocks, XOR Mn with Cn-1, then DES
            for (int i = 8; i < messageLength; i += 8) {
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = cbcXOR(stringAsBinaryArray, chainArray);
                ciphertext = DES(ciphertext, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, chainArray, 0, 64);
                System.arraycopy(ciphertext, 0, concatArray, i * 8, 64);
                System.out.println("array");
                show(concatArray);
            }
            finalArray = binaryArrayToInteger(concatArray, messageLength);
            show(finalArray);

            return finalArray;
            //The message is longer than 64 bits and requires padding
        } else {
            numArrays = messageLength / 8;
            int padding = messageLength % 8;
            int counter = 0;
            int[] concatArrayPad = new int[(messageLength * 8) + ((8 - padding) * 8)];
            int[] finalArray = new int[concatArrayPad.length];
            //For the first block, XOR m1 with IV, then DES
            for (int i = 0; i < 8; i += 8) {
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = cbcXOR(stringAsBinaryArray, ivAsBinaryArray);
                ciphertext = DES(ciphertext, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, chainArray, 0, 64);
                System.arraycopy(ciphertext, 0, concatArrayPad, 0, 64);
                counter++;

            }

            //Pad the last array to make 64 bit array, xor Mi with Ci-1, then DES
            for (int i = 8; i < messageLength; i += 8) {
                if (counter == numArrays) {
                    stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + padding));
                    for (int j = 0; j < 8 * (8 - padding); j++) {
                        stringAsBinaryArray[padding * 8 + j] = 0;
                    }
                    ciphertext = cbcXOR(stringAsBinaryArray, chainArray);
                    ciphertext = DES(ciphertext, keyAsBinaryArray);
                    System.arraycopy(ciphertext, 0, concatArrayPad, i * 8, 64);
                    finalArray = binaryArrayToInteger(concatArrayPad, messageLength + (8 - padding));

                    return finalArray;
                }
                //for blocks between the first and the last, XOR Mi with Ci-1, then DES
                stringAsBinaryArray = stringToIntegers(plaintext.substring(i, i + 8));
                ciphertext = cbcXOR(stringAsBinaryArray, chainArray);
                ciphertext = DES(ciphertext, keyAsBinaryArray);
                System.arraycopy(ciphertext, 0, concatArrayPad, i * 8, 64);
                counter++;
            }
        }

        return ciphertextError;
    }
    /**
     * cbcXOR is used in the CBC algorithm to XOR M1 with IV and Mn with Cn-1.
     * @param ciMinusOne The encrypted chunk or IV preceding Mn
     * @param m1 The message to be xor'd
     * @return the XOR'd array to be sent to DES
     */
    public static int[] cbcXOR(int[] ciMinusOne, int[] m1) {
        int[] xordArray = new int[64];

        for (int i = 0; i < 64; i++) {
            xordArray[i] = ciMinusOne[i] ^ m1[i];
        }
        return xordArray;
    }

    /**
     * stringToIntegers converts the message in string format to its ASCII
     * integer equivalent and then to binary form as integers.
     *
     * @param plaintext A string containing the message
     * @return An integer array containing the binary integers
     */
    public static int[] stringToIntegers(String plaintext) {
        int[] asciiToBinary = new int[64];
        //getBytes() takes the String and converts it to ASCII equivalent ints
        byte[] byteToAscii = plaintext.getBytes();

        int j = 0;
        for (int i = 0; i < byteToAscii.length; i++) {
            int num = byteToAscii[i];
            int digit = 0;
            int counter = 0;
            //converting each ascii integer into 8 bits. I had to go this longer way
            //as built in functions can return the binary equivalent but don't pad 0 in front
            while (counter < 8) {
                digit = (num / 128) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 64) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 32) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 16) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 8) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 4) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 2) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;
                digit = (num / 1) % 2;
                asciiToBinary[j] = digit;
                j++;
                counter++;

            }
        }

        return (asciiToBinary);

    }

    /**
     * binaryArrayToInteger takes an array of binary integers and converts them
     * to their base 10 equivalents which represent ascii codes.
     *
     * @param binaryArray An array containing binary integers
     * @param length The total length of the message, is variable
     * @return An int array of base 10 integers
     */
    public static int[] binaryArrayToInteger(int[] binaryArray, int length) {
        int[] integerArray = new int[length];

        for (int i = 0, j = 0; i < length * 8; i += 8) {
            int num = 0;
            //convert 8 bits a time into their ascii integer equivalent
            num += binaryArray[i] * 128;
            num += binaryArray[i + 1] * 64;
            num += binaryArray[i + 2] * 32;
            num += binaryArray[i + 3] * 16;
            num += binaryArray[i + 4] * 8;
            num += binaryArray[i + 5] * 4;
            num += binaryArray[i + 6] * 2;
            num += binaryArray[i + 7] * 1;
            integerArray[j] = num;
            j++;
        }

        return integerArray;

    }
    /**
     * initialPermutation performs the first permutation of the message text.
     *
     * @param plaintext An integer array of binary form
     * @return The permuted array
     */
    public static int[] initialPermutation(int[] plaintext) {
        int[] permutedOnce = new int[64];

        for (int i = 0; i < 64; i++) {
            permutedOnce[i] = plaintext[initialPermutation[i] - 1];
        }
        return permutedOnce;
    }

    /**
     * keyPermutation performs the initial permutation of the key and removes 8
     * parity bits
     *
     * @param key A 64 bit integer array of binary form
     * @return The 56 bit permuted key
     */
    public static int[] keyPermutation(int[] key) {
        int[] keyPermArray = new int[56];

        for (int i = 0; i < 56; i++) {
            keyPermArray[i] = key[keyPerm[i] - 1];
        }
        return keyPermArray;
    }

    /**
     * getC0 takes the 56 bit key and takes the first 28 bits
     *
     * @param keyUpper The 56 bit key
     * @return The first 28 bits
     */
    public static int[] getC0(int[] keyUpper) {
        int[] C0 = new int[28];

        System.arraycopy(keyUpper, 0, C0, 0, 28);

        return C0;
    }

    /**
     * getD0 takes the 56 bit key and takes the last 28 bits
     *
     * @param keyLower the 56 bit key
     * @return The last 28 bits
     */
    public static int[] getD0(int[] keyLower) {
        int[] D0 = new int[28];

        System.arraycopy(keyLower, 28, D0, 0, 28);

        return D0;
    }

    /**
     * rotateLeft performs the left shifts of the key,performs the permutation,
     * generates 16 keys to be used, sends the key to the mangler, XOR's the
     * results and sends them to sboxes and performs the final permutation.
     *
     * @param C0 The left half of the 56 bit key
     * @param D0 The right half of the 56 bit key
     * @param rn The 64 bit message
     * @return The 64 bit mangled and xor'd message
     */
    public static int[] rotateLeft(int[] C0, int[] D0, int[] rn) {
        int[] rnSplit = new int[32];
        int[] lnSplit = new int[32];
        int[] xorMangledArray = new int[32];
        int[] exitingArray = new int[64];
        int[] postMangle = new int[32];
        //16 keys
        int[] K1 = new int[48];
        int[] K2 = new int[48];
        int[] K3 = new int[48];
        int[] K4 = new int[48];
        int[] K5 = new int[48];
        int[] K6 = new int[48];
        int[] K7 = new int[48];
        int[] K8 = new int[48];
        int[] K9 = new int[48];
        int[] K10 = new int[48];
        int[] K11 = new int[48];
        int[] K12 = new int[48];
        int[] K13 = new int[48];
        int[] K14 = new int[48];
        int[] K15 = new int[48];
        int[] K16 = new int[48];
        int[] KiLeft = new int[28];
        int[] KiRight = new int[28];
        int[] KiLeftTemp = new int[28];
        int[] KiRightTemp = new int[28];

        int KiLength = 28;
        //performs the left circular shifts and permutes. 1,2,9, and 16 are 1 bit shifts, the rest are 2 bit
        //K1
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = C0[(i + 1) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = D0[(i + 1) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K1[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K1[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];

        }
        //K2
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 1) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 1) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K2[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K2[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //K3
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K3[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K3[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k4
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K4[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K4[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k5
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K5[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K5[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k6
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K6[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K6[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k7
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K7[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K7[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k8
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K8[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K8[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k9
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 1) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 1) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K9[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K9[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k10
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K10[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K10[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k11
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K11[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K11[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k12
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K12[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K12[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k13
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K13[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K13[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k14
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K14[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K14[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //k15
        for (int i = 0; i < KiLength; i++) {
            KiLeft[i] = KiLeftTemp[(i + 2) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRight[i] = KiRightTemp[(i + 2) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K15[i] = KiLeft[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K15[i + 24] = KiRight[perRoundKeyPermRight[i] - 29];
        }
        //k16
        for (int i = 0; i < KiLength; i++) {
            KiLeftTemp[i] = KiLeft[(i + 1) % 28];
        }
        for (int i = 0; i < KiLength; i++) {
            KiRightTemp[i] = KiRight[(i + 1) % 28];
        }
        for (int i = 0; i < 24; i++) {
            K16[i] = KiLeftTemp[perRoundKeyPermLeft[i] - 1];
        }
        for (int i = 0; i < 24; i++) {
            K16[i + 24] = KiRightTemp[perRoundKeyPermRight[i] - 29];
        }
        //Split the message into left and right halves
        System.arraycopy(rn, 32, rnSplit, 0, 32);
        System.arraycopy(rn, 0, lnSplit, 0, 32);

        int[] lnSplit1 = new int[32];
        //mangle the Rn using Kn, XOR with Ln to get Rn+1. Rn becomes Ln+1
        postMangle = mangler(rnSplit, K1);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }
        lnSplit = rnSplit;

        postMangle = mangler(xorMangledArray, K2);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];

        }

        postMangle = mangler(xorMangledArray, K3);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K4);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K5);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K6);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K7);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K8);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K9);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K10);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K11);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K12);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K13);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K14);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }

        postMangle = mangler(xorMangledArray, K15);
        System.arraycopy(xorMangledArray, 0, lnSplit, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit1[i];
        }

        postMangle = mangler(xorMangledArray, K16);
        System.arraycopy(xorMangledArray, 0, lnSplit1, 0, 32);
        for (int i = 0; i < 32; i++) {
            xorMangledArray[i] = postMangle[i] ^ lnSplit[i];
        }
        //concat left and right halves back into a 64 bit ciphertext
        System.arraycopy(lnSplit1, 0, exitingArray, 0, 32);
        System.arraycopy(xorMangledArray, 0, exitingArray, 32, 32);

        return exitingArray;
    }

    /**
     * mangler breaks the 32 bit half message, breaks into 8 4-bit chunks and
     * expands them to 6 bits by concatenating adjacent bits, XOR's them with Ki
     * and feeds to sboxes function.
     *
     * @param rn The right half of the message, 32 bits
     * @param ki The ki-th key
     * @return the mangled 32 bit array
     */
    public static int[] mangler(int[] rn, int[] ki) {
        int[] mangledArray = new int[32];
        int[] intermediateArray = new int[48];
        int[] xorArray = new int[48];
        //expand the 32 bit array into a 48 bit array
        intermediateArray[0] = rn[31];
        for (int i = 0; i < 5; i++) {
            intermediateArray[i + 1] = rn[i];
        }
        for (int i = 6; i < 12; i++) {
            intermediateArray[i] = rn[i - 3];
        }
        for (int i = 12; i < 18; i++) {
            intermediateArray[i] = rn[i - 5];
        }
        for (int i = 18; i < 24; i++) {
            intermediateArray[i] = rn[i - 7];
        }
        for (int i = 24; i < 30; i++) {
            intermediateArray[i] = rn[i - 9];
        }
        for (int i = 30; i < 36; i++) {
            intermediateArray[i] = rn[i - 11];
        }
        for (int i = 36; i < 42; i++) {
            intermediateArray[i] = rn[i - 13];
        }
        for (int i = 42; i < 47; i++) {
            intermediateArray[i] = rn[i - 15];
        }
        intermediateArray[47] = rn[0];
        //XOR the expanded array with the 48 bit key
        for (int i = 0; i < 48; i++) {
            xorArray[i] = intermediateArray[i] ^ ki[i];
        }
        //Send the 48 bit message to sBoxes function
        mangledArray = sBoxes(xorArray);
        //Send to sBoxPermute
        mangledArray = sBoxPermute(mangledArray);

        return mangledArray;

    }

    /**
     * sBoxes takes the 48 bit expanded message and uses sboxes to return a
     * 4-bit equivalent for each chunk of 6 bits. A different sbox is used for
     * each 6 bit chunk.
     *
     * @param toBeSBoxed The expanded array to be manipulated
     * @return a 32 bit array
     */
    public static int[] sBoxes(int[] toBeSBoxed) {
        int[] sBoxedArray = new int[32];
        int[] outerDigits = new int[2];
        int[] innerDigits = new int[4];
        int counter = 0;
        int copyCounter = 0;
        /**
         * Grab the outer and inner digits for each chunk and using switch
         * statements, feed them to each of 8 sBoxes
         */
        for (int i = 0; i < 48; i += 6) {
            System.arraycopy(toBeSBoxed, i, outerDigits, 0, 1);
            System.arraycopy(toBeSBoxed, i + 5, outerDigits, 1, 1);
            System.arraycopy(toBeSBoxed, i + 1, innerDigits, 0, 4);
            counter++;
            //Traverse the 2d array sboxes and find the 4-bit number it corresponds to
            switch (counter) {
                case 1:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s1[row][0]) && (outerDigits[1] == s1[row][1])) {

                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s1[0][col]) && (innerDigits[1] == s1[0][col + 1])
                                        && (innerDigits[2] == s1[0][col + 2]) && (innerDigits[3] == s1[0][col + 3])) {
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s1[row], l, sBoxedArray, 0 + copyCounter, 1);
                                        copyCounter++;

                                    }
                                }
                            }

                        }
                    }

                    break;

                case 2:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s2[row][0]) && (outerDigits[1] == s2[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s2[0][col]) && (innerDigits[1] == s2[0][col + 1])
                                        && (innerDigits[2] == s2[0][col + 2]) && (innerDigits[3] == s2[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s2[row], l, sBoxedArray, 4 + copyCounter, 1);
                                        copyCounter++;

                                    }
                                }
                            }

                        }
                    }
                    break;

                case 3:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s3[row][0]) && (outerDigits[1] == s3[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s3[0][col]) && (innerDigits[1] == s3[0][col + 1])
                                        && (innerDigits[2] == s3[0][col + 2]) && (innerDigits[3] == s3[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s3[row], l, sBoxedArray, 8 + copyCounter, 1);
                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;

                case 4:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s4[row][0]) && (outerDigits[1] == s4[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s4[0][col]) && (innerDigits[1] == s4[0][col + 1])
                                        && (innerDigits[2] == s4[0][col + 2]) && (innerDigits[3] == s4[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s4[row], l, sBoxedArray, 12 + copyCounter, 1);
                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;

                case 5:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s5[row][0]) && (outerDigits[1] == s5[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s5[0][col]) && (innerDigits[1] == s5[0][col + 1])
                                        && (innerDigits[2] == s5[0][col + 2]) && (innerDigits[3] == s5[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s5[row], l, sBoxedArray, 16 + copyCounter, 1);
                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;

                case 6:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s6[row][0]) && (outerDigits[1] == s6[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s6[0][col]) && (innerDigits[1] == s6[0][col + 1])
                                        && (innerDigits[2] == s6[0][col + 2]) && (innerDigits[3] == s6[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s6[row], l, sBoxedArray, 20 + copyCounter, 1);
                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;

                case 7:
                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s7[row][0]) && (outerDigits[1] == s7[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s7[0][col]) && (innerDigits[1] == s7[0][col + 1])
                                        && (innerDigits[2] == s7[0][col + 2]) && (innerDigits[3] == s7[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s7[row], l, sBoxedArray, 24 + copyCounter, 1);
                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;

                case 8:

                    for (int row = 1; row < 5; row++) {
                        if ((outerDigits[0] == s8[row][0]) && (outerDigits[1] == s8[row][1])) {
                            for (int col = 2; col < 65; col += 4) {
                                if ((innerDigits[0] == s8[0][col]) && (innerDigits[1] == s8[0][col + 1])
                                        && (innerDigits[2] == s8[0][col + 2]) && (innerDigits[3] == s8[0][col + 3])) {
                                    copyCounter = 0;
                                    for (int l = col; l < col + 4; l++) {
                                        System.arraycopy(s8[row], l, sBoxedArray, 28 + copyCounter, 1);

                                        copyCounter++;
                                    }
                                }
                            }

                        }
                    }
                    break;
                //uh-oh
                default:
                    System.out.println("Error in switch");
                    break;
            }

        }

        return sBoxedArray;
    }

    /**
     * sBoxPermute performs the final permutation at the end of 16 rounds of
     * sboxing.
     *
     * @param sBoxedArrayToPermute 32-bit array
     * @return the permuted array.
     */
    public static int[] sBoxPermute(int[] sBoxedArrayToPermute) {
        int[] permutedSbox = new int[32];

        for (int i = 0; i < 32; i++) {
            permutedSbox[i] = sBoxedArrayToPermute[sBoxPerm[i] - 1];
        }

        return permutedSbox;
    }

    /**
     * finalPermutations splits the array in half, switches the halves, and
     * performs our last permutation
     *
     * @param finalArray The 64 bit message
     * @return the final, encrypted ciphertext!
     */
    public static int[] finalPermutations(int[] finalArray) {
        int[] preCipherText = new int[64];
        int[] cipherText = new int[64];
        //switch the halves
        System.arraycopy(finalArray, 32, preCipherText, 0, 32);
        System.arraycopy(finalArray, 0, preCipherText, 32, 32);
        //The last permutation
        for (int i = 0; i < 64; i++) {
            cipherText[i] = preCipherText[finalPermutation[i] - 1];

        }
        //WE DID IT!!!
        return cipherText;
    }

    /**
     * show is a convenience function to display int arrays. Please feel free to
     * use this!
     *
     * @param passedArray An integer array of any size.
     */
    public static void show(int[] passedArray) {

        int counter = 0;
        for (int i = 0; i < passedArray.length; i++) {
            System.out.print(passedArray[i] + ",");
            counter++;
            if (counter % 8 == 0) {
                System.out.println();
            }
        }
        System.out.println();
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        int[] plaintext = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
        int[] key = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 0, 0, 1};

        int[] output = {1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
            0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1};

        int[] testingDes = DES(plaintext, key);
        System.out.println("**************************************");
        System.out.println("Testing DES... ");
        System.out.println("");
        System.out.println("Input plaintext is: ");
        show(plaintext);
        System.out.println("");
        System.out.println("Output ciphertext is: ");
        show(testingDes);

        System.out.println("**************************************");
        String plaintext1 = "I LOVE SECURITY";
        String key1 = "ABCDEFGH";
        System.out.println("Testing EBC...");
        System.out.println("");
        System.out.println("The input string is: ");
        System.out.println(plaintext1);
        System.out.println("");
        System.out.println("The ciphertext integer array is: ");
        int[] ecbReturn = ECB(plaintext1, key1);
        show(ecbReturn);

        System.out.println("**************************************");
        plaintext1 = "SECURITTSECURITT";
        key1 = "ABCDEFGH";
        String iv = "ABCDEFGH";
        System.out.println("Testing CBC...");
        System.out.println("");
        System.out.println("The input string is: ");
        System.out.println(plaintext1);
        System.out.println("");
        System.out.println("The ciphertext integer array is: ");
        int[] cbcReturn = CBC(plaintext1, key1, iv);
        show(cbcReturn);
        System.out.println("**************************************");
        String testerstring = "sec";
        String key2 = "ABCDEFGH";
        int[] ecbReturn1 = ECB(testerstring, key2);
        show(ecbReturn1);
        
        
    }

}
