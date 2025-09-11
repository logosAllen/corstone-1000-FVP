# Technical Report: TF-M BL1_2 Boot Stage Analysis for arm/corstone1000 FVP

## 1. Executive Summary & High-Level Role

The Trusted Firmware-M (TF-M) BL1_2 boot stage is the second part of the immutable bootloader in the TF-M secure boot process. It runs on the secure enclave (SE) processor and its primary role is to authenticate and load the second-stage bootloader (BL2) into RAM for execution. BL1_2 is stored in a secure, immutable storage medium, typically flash memory, and is loaded into the SE's SRAM by the first-stage bootloader (BL1_1), which is a small piece of code running from ROM.

The key responsibilities of BL1_2 are:

*   **Chain of Trust Verification:** Verify the authenticity and integrity of the BL2 image by checking its digital signature.
*   **Anti-Rollback Protection:** Prevent the execution of older, potentially vulnerable versions of BL2 by checking a security counter.
*   **Image Decryption:** Decrypt the BL2 image if it is encrypted.
*   **Execution Handoff:** After successful verification, transfer execution to the BL2 entry point.

This report provides a detailed analysis of the BL1_2 boot stage for the `arm/corstone1000` FVP platform, covering its execution flow, key functions, security mechanisms, and platform integration.

## 2. Execution Flow Diagram

The following Mermaid flowchart illustrates the main execution path of BL1_2:

```mermaid
graph TD
    A[Start] --> B{boot_platform_init()};
    B --> C{boot_platform_post_init()};
    C --> D{Loop: Try image 0, then image 1};
    D --> E{validate_image()};
    E --> F{copy_and_decrypt_image()};
    F --> G{validate_image_at_addr()};
    G --> H{is_image_signature_valid()};
    H -- Success --> I{is_image_security_counter_valid()};
    H -- Failure --> J{Try next image or recovery};
    I -- Success --> K{collect_boot_measurement()};
    I -- Failure --> J;
    J -- Both images failed --> L{boot_initiate_recovery_mode()};
    L -- Recovery failed --> M[PANIC];
    K --> N{boot_platform_quit()};
    N --> O[Jump to BL2];
```

## 3. Detailed Code Trace and Key Function Analysis

The main logic of BL1_2 is contained in `bl1/bl1_2/main.c`. The execution flow is as follows:

1.  The `main()` function is the entry point. It first calls `boot_platform_init()` and `boot_platform_post_init()` to perform platform-specific hardware initializations.
2.  It then enters a loop that attempts to validate and boot from one of two BL2 image slots (image 0 and image 1).
3.  For each image, it calls `validate_image()`, which in turn calls `copy_and_decrypt_image()` and `validate_image_at_addr()`.
4.  If both images fail to validate, it calls `boot_initiate_recovery_mode()`.
5.  If an image is successfully validated, it calls `collect_boot_measurement()` to record the BL2 image hash for measured boot.
6.  Finally, it calls `boot_platform_quit()` to clean up and jump to the BL2 entry point.

### Chain of Trust Verification

The chain of trust is verified in the `is_image_signature_valid()` function. In the Corstone-1000 FVP context, this function uses a post-quantum signature algorithm for verification.

*   **Signature Algorithm:** The `create_bl2_img.py` script uses the **HSS-LMS** (Hierarchical Signature System - Leighton-Micali Signature) algorithm to sign the BL2 image. This is a stateful hash-based signature scheme.
*   **Public Key Retrieval:** The public key used for verification is retrieved from OTP. The `pq_crypto_verify()` function is called with the key ID `TFM_BL1_KEY_ROTPK_0`, which corresponds to the root of trust public key stored in OTP. The `tfm_plat_otp_read()` function is used to read the key from OTP.

### Non-Security Functions (Hardware Initialization)

BL1_2 performs essential non-security hardware initializations in the `boot_hal_bl1_2.c` file:

*   **`boot_platform_init()`:** This function initializes `stdio` for logging purposes.
*   **`boot_platform_post_init()`:** This function initializes the flash controller driver (`FLASH_DEV_NAME`) to enable reading the BL2 image from flash.

### Execution Handoff

The execution handoff to BL2 is performed by the `boot_platform_quit()` function in `boot_hal_bl1_2.c`. This function:

1.  Uninitializes the crypto hardware accelerator and the flash driver.
2.  Resets the watchdog timer.
3.  Sets the Main Stack Pointer (MSP) to the value specified in the BL2 image's vector table.
4.  Calls `boot_jump_to_next_image()` to jump to the BL2 reset handler, effectively transferring control to BL2.

## 4. Key Data Structures and Security Mechanisms

### Data Structures

The primary data structure used for handling the firmware image is `bl1_2_image_t`, defined in `bl1/bl1_2/lib/interface/image.h`.

```c
__PACKED_STRUCT bl1_2_image_t {
    __PACKED_STRUCT  {
        uint8_t ctr_iv[CTR_IV_LEN];
        uint8_t sig[1452];
    } header;
    __PACKED_STRUCT {
        struct tfm_bl1_image_version_t version;
        uint32_t security_counter;

        __PACKED_STRUCT {
            uint32_t decrypt_magic;
            uint8_t pad[PAD_SIZE];
            uint8_t data[IMAGE_BL2_CODE_SIZE];
        } encrypted_data;
    } protected_values;
};
```

This structure contains:

*   **`header`:** Contains the CTR IV for AES-256 decryption and the signature of the `protected_values`.
*   **`protected_values`:** Contains the image version, security counter, and the encrypted BL2 image data.

### Security Hardening

BL1_2 implements several security mechanisms to protect against various attacks:

*   **Anti-Rollback Protection:** This is implemented in the `is_image_security_counter_valid()` function. It reads the current security counter value from a non-volatile (NV) counter in OTP and compares it with the security counter from the BL2 image. If the image's counter is not greater than the stored counter, the boot process is aborted.
*   **Fault Injection (FI) Countermeasures:** The code makes extensive use of a fault injection hardening library (`fih.h`). The `fih_int` type and `FIH_CALL` macros are used to introduce random delays and integrity checks to make it more difficult for an attacker to disrupt the boot process through fault injection attacks.

## 5. Platform Integration and Tooling

### HAL (Hardware Abstraction Layer)

The key HAL functions for BL1_2 on the Corstone-1000 platform are implemented in `platform/ext/target/arm/corstone1000/bl1/boot_hal_bl1_2.c`:

*   **`boot_platform_init()`:** Performs initial platform hardware setup.
*   **`boot_platform_post_init()`:** Performs post-initialization tasks, such as initializing the flash driver.
*   **`boot_platform_quit()`:** Cleans up the platform and jumps to the next boot stage.
*   **`bl1_image_get_flash_offset()`:** Returns the flash offset of a given BL2 image.

### Associated Tooling

The `create_bl2_img.py` script is used to generate and sign the BL2 image that BL1_2 verifies. This script performs the following steps:

1.  Derives a per-image encryption key using either CMAC or HKDF with the image security counter as input.
2.  Encrypts the BL2 image using AES-256 CTR.
3.  Signs the encrypted image and its metadata using the HSS-LMS algorithm.
4.  Constructs the final `bl1_2_image_t` structure.
