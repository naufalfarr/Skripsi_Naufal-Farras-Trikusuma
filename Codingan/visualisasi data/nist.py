import math
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt


def frequency_monobit_test(binary_data):
    """
    Perform the Frequency (Monobit) Test from NIST SP 800-22.

    Args:
        binary_data (str): Input binary data as a string of '0's and '1's.

    Returns:
        dict: Test result including pass/fail and p-value.
    """
    n = len(binary_data)

    # Count the number of 1s and 0s
    s_n = binary_data.count('1') - binary_data.count('0')

    # Test statistic
    s_obs = abs(s_n) / math.sqrt(n)

    # Compute the p-value
    p_value = math.erfc(s_obs / math.sqrt(2))

    return {
        "n": n,
        "s_obs": s_obs,
        "p_value": p_value,
        "pass": p_value >= 0.01  # Common threshold for randomness
    }


def validate_and_convert_hex_to_binary(hex_string):
    """
    Validate and convert a hexadecimal string to a binary string.

    Args:
        hex_string (str): Input hexadecimal string.

    Returns:
        str: Converted binary data as a string of '0's and '1's.
    """
    # Ensure the string length is even
    if len(hex_string) % 2 != 0:
        print("Hexadecimal string length is odd; appending a '0'.")
        hex_string += "0"

    try:
        byte_data = bytes.fromhex(hex_string)
        # Convert to binary representation
        binary_data = ''.join(format(byte, '08b') for byte in byte_data)
        return binary_data
    except ValueError as e:
        print("Error converting hex to binary. Check input:", e)
        return None


def analyze_randomness_nist(binary_data):
    """
    Analyze randomness using the NIST SP 800-22 Frequency (Monobit) Test.

    Args:
        binary_data (str): Binary string to analyze.

    Returns:
        dict: Results of the Frequency (Monobit) Test.
    """
    return frequency_monobit_test(binary_data)


# Example usage
if __name__ == "__main__":
    # Example plaintext and ciphertext
    plaintext = b"Encryption and Decryption Testing"

    # Convert plaintext to binary
    plaintext_binary = ''.join(format(byte, '08b') for byte in plaintext)

    # Perform NIST SP 800-22 Frequency (Monobit) Test
    plaintext_analysis_nist = analyze_randomness_nist(plaintext_binary)

    print("Plaintext Analysis (NIST SP 800-22):", plaintext_analysis_nist)

    # Analyze a hexadecimal string
    hex_data = ["559F8496A84B2D7C3F61FD7ECD445180A2B286BE43B416C6A2FEFFB0A0520B5", #CHACHA20
                "AA5082B7F3D8BA61629F325952BFF7928F4F5B97276BE0C59D7A6ED2051E8B46F22B2C3659EA637C4EB397FE666", #AES
                "",
                ""]

    # Convert hex to binary
    binary_data = validate_and_convert_hex_to_binary(hex_data[0])

    if binary_data:
        # Perform NIST SP 800-22 Frequency (Monobit) Test
        hex_analysis_nist = analyze_randomness_nist(binary_data)

        print("Ciphertext Analysis (NIST SP 800-22):", hex_analysis_nist)
    