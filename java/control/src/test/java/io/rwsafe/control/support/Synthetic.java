package io.rwsafe.control.support;

import java.util.Random;

/**
 * Synthetic test values built at runtime (AGENTS.md 4.5): a literal with a valid checksum or a secret shape would trip
 * the privacy gate and gitleaks, so no such literal exists in the tree.
 */
public final class Synthetic {

    private Synthetic() {
    }

    public static String tckn(long seed) {
        Random r = new Random(seed);
        int[] d = new int[11];
        d[0] = 1 + r.nextInt(9);
        for (int k = 1; k < 9; k++) {
            d[k] = r.nextInt(10);
        }
        d[9] = Math.floorMod((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7]), 10);
        int sum = 0;
        for (int k = 0; k < 10; k++) {
            sum += d[k];
        }
        d[10] = sum % 10;
        StringBuilder s = new StringBuilder();
        for (int v : d) {
            s.append(v);
        }
        return s.toString();
    }

    public static String iban(long seed) {
        Random r = new Random(seed);
        StringBuilder bban = new StringBuilder();
        for (int k = 0; k < 22; k++) {
            bban.append(r.nextInt(10));
        }
        int rem = 0;
        for (char c : (bban + "292700").toCharArray()) {
            rem = (rem * 10 + (c - '0')) % 97;
        }
        int check = 98 - rem;
        return "T" + "R" + (check < 10 ? "0" : "") + check + bban;
    }

    public static String card(long seed) {
        Random r = new Random(seed);
        int[] d = new int[16];
        d[0] = 4;
        for (int k = 1; k < 15; k++) {
            d[k] = r.nextInt(10);
        }
        int sum = 0;
        for (int k = 14, pos = 0; k >= 0; k--, pos++) {
            int v = d[k];
            if (pos % 2 == 0) {
                v *= 2;
                if (v > 9) {
                    v -= 9;
                }
            }
            sum += v;
        }
        d[15] = (10 - sum % 10) % 10;
        StringBuilder s = new StringBuilder();
        for (int v : d) {
            s.append(v);
        }
        return s.toString();
    }

    /** An access-key-shaped value: vendor prefix plus sixteen synthetic characters. */
    public static String awsKey() {
        return "AK" + "IA" + "SYNTHETIC0000000".toUpperCase();
    }

    public static String githubToken() {
        return "gh" + "p_" + "synthetic".repeat(4);
    }
}
